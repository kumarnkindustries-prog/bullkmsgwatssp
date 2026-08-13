# BullkMsgWatssp — Complete Website + Backend

## What is included
- Branded responsive web dashboard
- One-time admin setup/login
- SQLite database with WAL mode
- Contact import: CSV/XLSX/XLS
- Opt-in field and group segmentation
- WhatsApp template records
- Campaign creation and controlled sequential sending
- Server-side WhatsApp Cloud API call
- Encrypted storage of the WhatsApp access token
- Webhook verification endpoint
- Docker + docker-compose
- Persistent `/data` volume

## Important
This is a production-oriented starter, but it is **not possible to make a WhatsApp sender fully live without Meta/WhatsApp-side credentials and an approved sender/template**. Those credentials must come from your WhatsApp Business setup.

The system intentionally sends only to contacts marked `opted_in=1` and uses template messages. Do not use it for unsolicited spam.

## Fastest deployment
### Docker
1. Install Docker on your VPS/server.
2. Put this project on the server.
3. Run:
   `docker compose up -d --build`
4. Open port 3000 (or put Nginx/Cloudflare in front).
5. Open the website. On first launch create your admin account.
6. Go to **WhatsApp Setup** and enter the Phone Number ID and access token.
7. Add an approved template name.
8. Import your opted-in contacts.
9. Create a campaign.

### Without Docker
`npm install`
`npm start`

## Recommended production hardening
- Put HTTPS in front of the app.
- Use a long random JWT_SECRET.
- Use a persistent disk for `/data`.
- Configure Meta webhook events and point the callback to `/webhook`.
- Add monitoring/backups.
- For very large campaigns, move sending into a dedicated Redis/BullMQ worker and tune throughput to your WhatsApp Business limits.

## Data format
CSV/XLSX headers:
`name,phone,group,opted_in`

Example:
`Ravi,919876543210,Retailers,1`

Phone numbers should be in international format, preferably with country code.
