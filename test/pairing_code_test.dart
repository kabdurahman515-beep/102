import 'dart:convert';

import 'package:control_api/auth/device_auth.dart';
import 'package:control_api/models/device.dart';
import 'package:control_api/routes/devices.dart';
import 'package:control_api/routes/admin.dart';
import 'package:control_api/storage/app_state.dart';
import 'package:shelf/shelf.dart';
import 'package:test/test.dart';

const _admin = 'test-admin-token-12345678901234567890';

Handler _deviceHandler(AppState s) => const Pipeline()
    .addMiddleware(deviceAuthMiddleware(s))
    .addHandler(deviceRoutes(s).call);

Future<Response> _request(Handler h, String method, String path,
    {Map<String, dynamic>? body, String? bearer}) => Future.sync(() => h(Request(
      method, Uri.parse('http://localhost$path'),
      body: body == null ? null : jsonEncode(body),
      headers: {
        if (body != null) 'content-type': 'application/json',
        if (bearer != null) 'authorization': 'Bearer $bearer',
      },
    )));

Future<Map<String, dynamic>> _json(Response r) async =>
    jsonDecode(await r.readAsString()) as Map<String, dynamic>;

void main() {
  group('website-approved device registration', () {
    test('registration creates a pending request and returns a poll secret', () async {
      final state = AppState();
      final handler = _deviceHandler(state);
      final response = await _request(handler, 'POST', '/devices/register', body: {
        'device_name': 'Test phone', 'platform': 'android',
      });
      expect(response.statusCode, 202);
      final body = await _json(response);
      expect(body['status'], 'pending');
      expect((body['poll_secret'] as String).length, 64);
      expect(state.pendingRegistrations.length, 1);
      expect(state.pendingRegistrations.values.single['status'], 'pending');
    });

    test('registration polling secret is required', () async {
      final state = AppState();
      final handler = _deviceHandler(state);
      final response = await _request(handler, 'POST', '/devices/register', body: {
        'device_name': 'Test PC', 'platform': 'windows',
      });
      final body = await _json(response);
      final poll = await _request(handler, 'GET', '/devices/registration/${body['registration_id']}');
      expect(poll.statusCode, 401);
      final authorized = await _request(handler, 'GET', '/devices/registration/${body['registration_id']}', bearer: body['poll_secret'] as String);
      expect(authorized.statusCode, 200);
      expect((await _json(authorized))['status'], 'pending');
    });

    test('legacy pairing endpoints cannot bypass owner approval', () async {
      final handler = _deviceHandler(AppState());
      expect((await _request(handler, 'POST', '/devices/pair', body: {})).statusCode, 410);
      expect((await _request(handler, 'POST', '/pairing-codes', body: {})).statusCode, 410);
    });

    test('old devices without expiry remain permanent', () {
      final device = Device(id: 'old', name: 'Old device', bearerTokenHash: 'hash',
          pairedAt: DateTime.now().toUtc(), lastSeenAt: DateTime.now().toUtc());
      expect(device.expiresAt, isNull);
    });
  });
}
