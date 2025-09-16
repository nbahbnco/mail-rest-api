curl -X POST http://localhost:18080/send-email \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test" \
  -d '{
    "to": "iviso@nubodata.com",
    "subject": "Test Email from Mail REST API",
    "body": "<h1>Hello World!</h1><p>This is a test email sent from the queued mail REST API.</p><p>The email will be delivered at a rate of 1 per second.</p>"
  }'