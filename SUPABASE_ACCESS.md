# Supabase UI Access Instructions

## Development Environment (192.168.0.201 - Container 122)

The Supabase instance at 192.168.0.201 has the following services:

### Available Services:
- **Kong API Gateway**: http://192.168.0.225:8000
- **PostgreSQL (via pooler)**: 192.168.0.225:5432
- **Analytics**: http://192.168.0.225:4000

### Accessing Supabase Studio:
Unfortunately, the Supabase Studio UI is running internally on port 3000 but is NOT exposed externally (port 3000 is used by Gitea). 

To access the Supabase Studio, you have two options:

#### Option 1: SSH Port Forwarding (Recommended)
```bash
# From your local machine, create an SSH tunnel:
ssh -L 3333:localhost:3000 root@192.168.0.201 'pct enter 122 -- docker exec -it supabase-studio sh'

# Then access in your browser:
http://localhost:3333
```

#### Option 2: Access via Kong Gateway
The Supabase Studio is accessible through the Kong gateway:
```
http://192.168.0.225:8000/
```

You'll need the service key or anon key to authenticate. These can be found in the Supabase configuration.

### Getting the Supabase Keys:
```bash
# Get the anon key
ssh root@192.168.0.201 'pct exec 122 -- docker exec supabase-kong env | grep ANON_KEY'

# Get the service role key
ssh root@192.168.0.201 'pct exec 122 -- docker exec supabase-kong env | grep SERVICE_KEY'
```

## Production Environment (192.168.0.202 - LXC 998)

The production server at 192.168.0.202 (LXC 998) appears to only have the Kong Guard AI application container running, not a full Supabase stack.

- **Container IP**: 192.168.0.228
- **Running Container**: kongguard-ai-app

This production setup seems to connect to the development Supabase instance for database operations.

## Direct Database Access

For direct PostgreSQL access (bypassing the UI):

### Development Database:
```bash
# Direct psql access
ssh root@192.168.0.201 'pct exec 122 -- docker exec -it supabase-db psql -U supabase_admin -d postgres'

# Once connected, switch to Kong Guard schema:
SET search_path TO kongguard, public;
```

### Using pgAdmin or DBeaver:
- **Host**: 192.168.0.225
- **Port**: 5432
- **Database**: postgres
- **Username**: supabase_admin
- **Password**: Jlwain@321
- **Schema**: kongguard

## Quick Connection Test:
```bash
# Test if Supabase is accessible
curl http://192.168.0.225:8000/rest/v1/ -H "apikey: YOUR_ANON_KEY"
```

## Notes:
- The Supabase Studio web interface requires authentication with either the anon or service role key
- Port 3000 on the host is occupied by Gitea, so Studio isn't directly accessible
- All database operations can be done via the Python interface in `supabase_production.py`
- The Kong gateway on port 8000 provides the REST API access to Supabase