# 🐳 Docker Environment - Ice Skating Server

This directory contains the complete Docker environment for running the Ice Skating game's multiplayer infrastructure. The setup includes the dedicated game server, database, and API services required for online gameplay.

## 📋 Prerequisites

- Docker and Docker Compose installed
- **Important**: A compatible dedicated server build of the game exported to `docker/game_server/build/`

## 🏗️ Architecture Overview

The Docker environment consists of:

- **🎮 Game Server**: Headless Godot instance running the dedicated server
- **🗄️ MariaDB Database**: Stores user data, leaderboards, and game statistics  
- **🌐 Public API**: Handles client authentication and public game data
- **🔒 Private API**: Internal API for server-to-database communication
- **📊 PHPMyAdmin**: Database management interface (development only)

## ⚙️ Setup Instructions

### 1. Export Dedicated Server Build (If you did any changes)

**Critical Step**: Before running the Docker environment, you must export a dedicated server build from Godot:

1. Open the project in Godot 4.4
2. Go to `Project > Export`
3. Select the "Dedicated Server" export preset
4. Export the build to: `docker/game_server/build/`
5. Ensure the executable is named appropriately for your platform

```bash
# Expected structure after export:
docker/
└── game_server/
    └── build/
        └── game_server.x86_64  # Linux build
        # or
        └── game_server.exe     # Windows build
```

### 2. Environment Configuration

Copy and configure the environment file:

```bash
cp .env.example .env  # If available
# Edit .env with your specific configurations
```

### 3. Start the Environment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## 🔧 Service Details

### Game Server
- **Port**: 7000 (configurable)
- **Type**: Headless Godot dedicated server
- **Function**: Authoritative multiplayer game logic

### MariaDB Database
- **Port**: 3306 (internal)
- **Database**: gamedb
- **Function**: Persistent storage for users and leaderboards

### Public API
- **Port**: 3000
- **Function**: Client authentication and public data access

### Private API  
- **Port**: 3001 (internal)
- **Function**: Server-side database operations

### PHPMyAdmin (Development)
- **Port**: 8080
- **Function**: Database administration interface

## 🛠️ Development Commands

```bash
# Build services
make build

# Start development environment
make dev

# View service logs
make logs

# Reset database
make reset-db

# Clean everything
make clean
```

## 🚀 Production Deployment

For production deployment:

1. Ensure proper environment variables are set
2. Remove development services (PHPMyAdmin)
3. Configure proper SSL/TLS certificates
4. Set up monitoring and logging
5. Configure firewall rules

## 🔍 Troubleshooting

### Game Server Won't Start

- If you encounter an error relative the start_server.sh file you probably have to change the EOF of the file
- Verify the dedicated server build exists in `docker/game_server/build/`
- Check the executable has proper permissions
- Review game server logs: `docker-compose logs game_server`

### Database Connection Issues
- Ensure MariaDB is fully initialized: `docker-compose logs mariadb`
- Check network connectivity between services
- Verify environment variables are correctly set

### API Services Not Responding
- Check if all services are running: `docker-compose ps`
- Verify port configurations match your setup
- Review API logs for specific error messages

## 📁 Directory Structure

```
docker/
├── README.md                    # This file
├── docker-compose.yml           # Main orchestration file
├── Makefile                     # Development commands
├── .env                         # Environment variables
├── game_server/
│   ├── build/                   # ⚠️  Export dedicated server here
│   ├── Dockerfile.gameserver    # Game server container
│   └── start_server.sh          # Server startup script
├── api_public/
│   ├── Dockerfile               # Public API container
│   ├── package.json             # Node.js dependencies
│   └── server.js                # Public API implementation
├── api_private/
│   ├── Dockerfile               # Private API container  
│   ├── package.json             # Node.js dependencies
│   └── server.js                # Private API implementation
└── sql/
    └── init.sql                 # Database initialization
```

## 🔐 Security Notes

- Change default passwords in production
- Use environment variables for sensitive data
- Restrict network access to internal APIs
- Regular security updates for all components

---

*This Docker environment provides a complete multiplayer infrastructure for Ice Skating, enabling global online gameplay with proper authentication and leaderboard functionality.*