import 'dart:convert';

import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';

import '../ai_tools/ai_tool_registry.dart';
import '../auth/device_auth.dart';
import '../models/activity.dart';
import '../models/api_key.dart';
import '../models/errors.dart';
import '../models/device.dart';
import '../storage/app_state.dart';
import '../util/crypto_utils.dart';
import '../util/http_utils.dart';

Router deviceRoutes(AppState state) {
  final router = Router();

  // Website-approved registration. Pending requests expire after 24h; this is
  // deliberately separate from the approved device credential lifetime.
  router.post('/devices/register', (Request request) async {
    final parsed = await readJsonObject(request);
    if (!parsed.isOk) return parsed.error!;
    final body = parsed.body!;
    final name = (body['device_name'] as String? ?? '').trim();
    final platform = body['platform'];
    if (name.isEmpty || name.length > 100) return ApiError.invalidRequest('Device name required (1-100 chars)');
    if (platform is! String || !{'android','windows','linux'}.contains(platform)) return ApiError.invalidRequest('Invalid platform');
    final now = DateTime.now().toUtc();
    state.pendingRegistrations.removeWhere((_, item) {
      final terminal = item['status'] != 'pending';
      final created = DateTime.tryParse(item['created_at'] as String? ?? '');
      return terminal && created != null && created.isBefore(now.subtract(const Duration(days: 7)));
    });
    final pendingCount = state.pendingRegistrations.values.where((item) => item['status'] == 'pending').length;
    if (pendingCount >= 500) return ApiError.rateLimited('Too many pending registrations');
    final id = 'reg_${randomHex(16)}';
    final pollSecret = randomHex(32);
    state.pendingRegistrations[id] = {
      'id': id, 'name': name, 'platform': platform,
      'created_at': now.toIso8601String(),
      'request_expires_at': now.add(const Duration(hours: 24)).toIso8601String(),
      'poll_secret_hash': hashSecretUtil(pollSecret), 'status': 'pending',
    };
    await state.persist();
    return Response(202, body: jsonEncode({'registration_id': id, 'poll_secret': pollSecret, 'status': 'pending', 'poll_interval_seconds': 5}), headers: {'content-type':'application/json','cache-control':'no-store'});
  });

  router.get('/devices/registration/<id>', (Request request, String id) async {
    final item = state.pendingRegistrations[id];
    if (item == null) return ApiError.notFound('Registration not found');
    final supplied = request.headers['authorization']?.replaceFirst(RegExp(r'^Bearer\s+', caseSensitive:false), '') ?? request.url.queryParameters['secret'] ?? '';
    if (!constantTimeEquals(hashSecretUtil(supplied), item['poll_secret_hash'] as String)) return unauthorized('Registration polling credential invalid');
    final now = DateTime.now().toUtc();
    if (DateTime.parse(item['request_expires_at'] as String).isBefore(now) && item['status'] == 'pending') {
      item['status'] = 'expired'; await state.persist();
    }
    if (item['status'] == 'approved' || item['status'] == 'claimed') {
      final existingId = item['device_id'] as String?;
      Device? device = existingId == null ? null : state.devices[existingId];
      String token = Device.generateToken();
      if (device == null) {
        var deviceId = Device.generateId(); while (state.devices.containsKey(deviceId)) { deviceId = Device.generateId(); }
        device = Device(id: deviceId, name: item['name'] as String, platform: item['platform'] as String, bearerTokenHash: hashSecretUtil(token), pairedAt: now, lastSeenAt: now, expiresAt: item['access_expires_at'] == null ? null : DateTime.parse(item['access_expires_at'] as String));
        state.devices[deviceId] = device; item['device_id'] = deviceId;
      } else {
        device.bearerTokenHash = hashSecretUtil(token); state.devices.touch(); state.revalidateListeners();
      }
      item['status'] = 'claimed'; await state.persist();
      return Response.ok(jsonEncode({'status':'approved','device_id':device.id,'bearer_token':token,'expires_at':device.expiresAt?.toIso8601String()}), headers:{'content-type':'application/json','cache-control':'no-store'});
    }
    return Response.ok(jsonEncode({'status': item['status']}), headers:{'content-type':'application/json','cache-control':'no-store'});
  });

  // POST /pairing-codes — owner ek-baar-use, chhota-umr pairing code
  // issue karta hai. Auth: (a) pehle se paired device ka bearer token, ya
  // (b) `Authorization: Bearer <ADMIN_SECRET>` (pehla device bootstrap
  // karne ke liye). Response mein code sirf isi baar milta hai.
  router.post('/pairing-codes', (Request request) async {
    return Response(410, body: jsonEncode({'error':'owner_approval_required','message':'Pairing codes have been replaced by website approval.'}), headers: {'content-type':'application/json'});
  });

  // Legacy instant-pair endpoint is intentionally retired; owner approval is mandatory.
  router.post('/devices/pair', (Request request) async {
    return Response(410, body: jsonEncode({'error':'owner_approval_required','message':'Use POST /devices/register and wait for website approval.'}), headers: {'content-type':'application/json'});
  });

  // DELETE /devices/{id} — Item 21: device khud ko unpair karta hai.
  // Uski API keys, connector credentials, tasks, custom capabilities
  // aur activity log sab hat jaate hain, aur live connection close hoti
  // hai. Sirf device ka apna token (API key se nahi).
  router.delete('/devices/<id>', (Request request, String id) async {
    final authError = authorizeForDevice(request, id, allowApiKey: false);
    if (authError != null) return authError;
    final removed = await state.removeDevice(id);
    if (!removed) return ApiError.notFound('Device not found');
    return Response(204);
  });

  // POST /devices/{id}/rotate-token — Item 21: naya bearer token; purana
  // turant invalid. Naya token sirf isi response mein ek baar.
  router.post('/devices/<id>/rotate-token', (Request request, String id) async {
    final authError = authorizeForDevice(request, id, allowApiKey: false);
    if (authError != null) return authError;
    final device = state.devices[id];
    if (device == null) return ApiError.notFound('Device not found');
    final token = Device.generateToken();
    device.bearerTokenHash = hashSecretUtil(token);
    state.devices.touch(); // Item 22: token-index invalidate
    state.revalidateListeners(); // purane token se khule WS band
    await state.persist();
    // Purani (ab invalid token wali) live connection band karo; client
    // naye token se reconnect karega.
    final conn = state.deviceConnections.remove(id);
    try {
      await conn?.sink.close(4002, 'token rotated');
    } catch (_) {}
    return Response.ok(
      jsonEncode({'device_id': id, 'bearer_token': token}),
      headers: {'content-type': 'application/json'},
    );
  });

  // GET /devices/{id}/status — Item 8: ab authenticated (device ka apna
  // token ya us device ki API key). Pehle koi bhi device id jaan kar
  // location/battery padh sakta tha.
  router.get('/devices/<id>/status', (Request request, String id) async {
    final authError = authorizeForDevice(request, id);
    if (authError != null) return authError;
    final device = state.devices[id];
    if (device == null) {
      return ApiError.notFound('Device not found');
    }
    // P1-05 — `agent_connected` `device.state` se independent hai.
    return Response.ok(
      jsonEncode({
        ...device.toStatusJson(),
        'agent_connected': state.deviceConnections.containsKey(id),
      }),
      headers: {'content-type': 'application/json'},
    );
  });

  // POST /devices/{id}/location — device apni location report karta hai.
  router.post('/devices/<id>/location', (Request request, String id) async {
    final unauth = _requireDeviceMatching(request, id);
    if (unauth != null) return unauth;

    final device = state.devices[id];
    if (device == null) {
      return ApiError.notFound('Device not found');
    }
    final parsed = await readJsonObject(request);
    if (!parsed.isOk) return parsed.error!;
    // Item 18: shape/range validation + sirf whitelisted fields store.
    final location = sanitizeLocation(parsed.body!);
    if (location == null) {
      return ApiError.invalidRequest(
          '"latitude" (-90..90) aur "longitude" (-180..180) numbers chahiye');
    }
    device.lastLocation = location;
    state.logActivity(ActivityEvent(
      eventType: 'location_updated',
      deviceId: id,
      timestamp: DateTime.now().toUtc(),
      status: 'success',
      actor: 'device_agent',
    ));
    await state.persist();
    return Response(204);
  });

  // POST /devices/{id}/network — Item 32: device apna network status
  // report karta hai (`connected`, optional `ssid`, `connection_type`).
  router.post('/devices/<id>/network', (Request request, String id) async {
    final unauth = _requireDeviceMatching(request, id);
    if (unauth != null) return unauth;
    final device = state.devices[id];
    if (device == null) return ApiError.notFound('Device not found');
    final parsed = await readJsonObject(request);
    if (!parsed.isOk) return parsed.error!;
    final network = sanitizeNetwork(parsed.body!);
    if (network == null) {
      return ApiError.invalidRequest('"connected" (bool) required hai');
    }
    device.lastNetwork = network;
    await state.persist();
    return Response(204);
  });

  // GET /devices/{id}/activity?limit=N — Item 8: authenticated.
  router.get('/devices/<id>/activity', (Request request, String id) async {
    final authError = authorizeForDevice(request, id);
    if (authError != null) return authError;
    final limitParam = request.url.queryParameters['limit'];
    final limit = (int.tryParse(limitParam ?? '') ?? 50).clamp(1, 500).toInt();
    final events = state.activityLog
        .where((e) => e.deviceId == id)
        .toList()
        .reversed
        .take(limit)
        .map((e) => e.toJson())
        .toList();
    return Response.ok(jsonEncode(events),
        headers: {'content-type': 'application/json'});
  });

  // GET /devices/{id}/ai-tools — P1-02: AI Tool Registry. API-key auth.
  // Item 9: key sirf *apne* device ke tools dekh sakti hai.
  router.get('/devices/<id>/ai-tools', (Request request, String id) async {
    final apiKey = request.context['apiKey'];
    if (apiKey == null) {
      return unauthorized('Valid scoped API key required (device bearer token nahi)');
    }
    final key = apiKey as ApiKeyRecord;
    if (key.deviceId != id) {
      return ApiError.scopeDenied('Yeh API key is device ki nahi hai');
    }

    final device = state.devices[id];
    if (device == null) {
      return ApiError.notFound('Device not found');
    }

    // Item 15: sirf is device ki registered custom capabilities.
    final tools = buildAiTools(
      device: device,
      scope: key.scope,
      customManifests: state.customCapabilityManifests
          .where((m) =>
              m['registered_by'] == null || m['registered_by'] == device.id)
          .toList(),
    );

    return Response.ok(
      jsonEncode({
        'device_id': id,
        'platform': device.platform,
        'tools': tools.map((t) => t.toJson()).toList(),
      }),
      headers: {'content-type': 'application/json'},
    );
  });

  return router;
}

Response? _requireDeviceMatching(Request request, String expectedDeviceId) {
  final device = request.context['device'];
  if (device == null) {
    return unauthorized('Device auth required');
  }
  if ((device as dynamic).id != expectedDeviceId) {
    return ApiError.forbidden("Token doesn't match this device");
  }
  return null;
}
