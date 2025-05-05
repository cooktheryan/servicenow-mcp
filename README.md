# ServiceNow MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server that interfaces with ServiceNow, allowing AI agents to access and manipulate ServiceNow data through a secure API. This server enables natural language interactions with ServiceNow, making it easier to search for records, update them, and manage scripts.

## Features

### Resources

- `servicenow://incidents`: List recent incidents
- `servicenow://incidents/{number}`: Get a specific incident by number
- `servicenow://users`: List users
- `servicenow://knowledge`: List knowledge articles
- `servicenow://tables`: List available tables
- `servicenow://tables/{table}`: Get records from a specific table
- `servicenow://schema/{table}`: Get the schema for a table

### Tools

#### Basic Tools
- `create_incident`: Create a new incident with human-readable formatted output
- `get_record`: Get a specific record by sys_id with human-readable formatted output for incidents

## Installation

### From PyPI

```bash
pip install mcp-server-servicenow
```

### From Source

```bash
git clone https://github.com/michaelbuckner/servicenow-mcp.git
cd servicenow-mcp
pip install -e .
```

## Usage

### Command Line

Run the server using the Python module:

```bash
python -m mcp_server_servicenow.cli --url "https://your-instance.service-now.com/" --username "your-username" --password "your-password"
```

Or use environment variables:

```bash
export SERVICENOW_INSTANCE_URL="https://your-instance.service-now.com/"
export SERVICENOW_USERNAME="your-username"
export SERVICENOW_PASSWORD="your-password"
python -m mcp_server_servicenow.cli
```

### Configuration in Cline

To use this MCP server with Cline, add the following to your MCP settings file:

```json
{
  "mcpServers": {
    "servicenow": {
      "command": "/path/to/your/python/executable",
      "args": [
        "-m",
        "mcp_server_servicenow.cli",
        "--url", "https://your-instance.service-now.com/",
        "--username", "your-username",
        "--password", "your-password"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Note:** Make sure to use the full path to the Python executable that has the `mcp-server-servicenow` package installed.

## Usage Examples

### Creating Incidents

To create a new incident, use the `create_incident` tool with a dictionary containing at least the required fields:

```
# Create an incident with the required fields
create_incident(incident={"short_description": "Email service is down", "description": "Users are unable to send or receive emails."})

# Create an incident with additional fields
create_incident(incident={
  "short_description": "Network outage", 
  "description": "The network is down in the east wing offices.", 
  "category": "Network", 
  "subcategory": "LAN",
  "impact": 1,  # High impact
  "urgency": 1  # High urgency
})
```

Note: Previously, string inputs were supported but have been removed to ensure consistent behavior.

### Getting Records

You can retrieve specific records:

```
Get incident INC0010001
Get record sys_user 5f7c2a374f510300a9a95144836d4324
```

## Authentication Methods

The server supports multiple authentication methods:

1. **Basic Authentication**: Username and password
2. **Token Authentication**: OAuth token
3. **OAuth Authentication**: Client ID, Client Secret, Username, and Password

## Development

### Prerequisites

- Python 3.8+
- ServiceNow instance with API access

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/michaelbuckner/servicenow-mcp.git
cd servicenow-mcp

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
