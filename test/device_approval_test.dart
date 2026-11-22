import 'dart:convert';

import 'package:control_api/routes/admin.dart';
import 'package:control_api/routes/devices.dart';
import 'package:control_api/storage/app_state.dart';
import 'package:shelf/shelf.dart';
import 'package:test/test.dart';

const _adminToken = 'device-approval-test-admin-token-0123456789';

Future<Response> _send(Handler handler, String method, String path,
    {Map<String, dynamic>? body, String? token}) => Future.sync(() => handler(Request(
      method, Uri.parse('http://localhost$path'),
      body: body == null ? null : jsonEncode(body),
      headers: {
        if (body != null) 'content-type': 'application/json',
        if (token != null) 'authorization': 'Bearer $token',
      },
    )));

Future<Map<String, dynamic>> _read(Response response) async =>
    jsonDecode(await response.readAsString()) as Map<String, dynamic>;

void main() {
  test('owner approval issues a credential with selected expiry', () async {
    final state = AppState();
    final deviceHandler = deviceRoutes(state).call;
    final registered = await _send(deviceHandler, 'POST', '/devices/register', body: {
      'device_name': 'Approval test phone', 'platform': 'android',
    });
    final registration = await _read(registered);
    final registrationId = registration['registration_id'] as String;
    final pollSecret = registration['poll_secret'] as String;

    debugAdminTokenOverride = _adminToken;
    try {
      final adminHandler = adminRoutes(state, (request) async => Response.ok('{}')).call;
      final approval = await _send(adminHandler, 'POST', '/admin/pending-devices/$registrationId/approve',
          token: _adminToken, body: {'unit':'days','amount':7});
      expect(approval.statusCode, 200);

      final poll = await _send(deviceHandler, 'GET', '/devices/registration/$registrationId', token: pollSecret);
      expect(poll.statusCode, 200);
      final credential = await _read(poll);
      expect(credential['status'], 'approved');
      expect(credential['bearer_token'], isA<String>());
      expect(credential['expires_at'], isA<String>());
      expect(state.devices.length, 1);
      expect(state.devices.values.single.expiresAt, isNotNull);
    } finally {
      debugAdminTokenOverride = null;
    }
  });

  test('permanent approval has no expiry', () async {
    final state = AppState();
    final registered = await _send(deviceRoutes(state).call, 'POST', '/devices/register', body: {
      'device_name': 'Permanent test', 'platform': 'linux',
    });
    final registration = await _read(registered);
    debugAdminTokenOverride = _adminToken;
    try {
      final adminHandler = adminRoutes(state, (request) async => Response.ok('{}')).call;
      final approval = await _send(adminHandler, 'POST', '/admin/pending-devices/${registration['registration_id']}/approve',
          token: _adminToken, body: {'unit':'permanent'});
      expect(approval.statusCode, 200);
      final poll = await _send(deviceRoutes(state).call, 'GET', '/devices/registration/${registration['registration_id']}', token: registration['poll_secret'] as String);
      final credential = await _read(poll);
      expect(credential['expires_at'], isNull);
      expect(state.devices.values.single.expiresAt, isNull);
    } finally {
      debugAdminTokenOverride = null;
    }
  });
}
