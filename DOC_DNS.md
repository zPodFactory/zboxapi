# DNS Management API

The zboxapi includes a comprehensive DNS management system that allows you to create, read, update, and delete DNS records in `/etc/hosts` with proper validation and automatic dnsmasq configuration reloading.

## Overview

The DNS management system provides a RESTful API for managing DNS records in the system's `/etc/hosts` file. It includes automatic dnsmasq configuration reloading to ensure DNS changes take effect immediately.

## API Endpoints

### 1. List All DNS Records
**GET** `/dns`

Returns all configured DNS records from `/etc/hosts`.

**Response:**
```json
[
    {
        "ip": "127.0.0.1",
        "hostname": "localhost"
    },
    {
        "ip": "192.168.1.100",
        "hostname": "server1.example.com"
    },
    {
        "ip": "192.168.1.101",
        "hostname": "server2.example.com"
    }
]
```

### 2. Get Specific DNS Record
**GET** `/dns/{ip}/{hostname}`

Returns information about a specific DNS record.

**Parameters:**
- `ip`: IPv4 address (e.g., `192.168.1.100`)
- `hostname`: Valid hostname (e.g., `server1.example.com`)

**Response:**
```json
{
    "ip": "192.168.1.100",
    "hostname": "server1.example.com"
}
```

### 3. Add DNS Record
**POST** `/dns`

Creates a new DNS record.

**Request Body:**
```json
{
    "ip": "192.168.1.100",
    "hostname": "server1.example.com"
}
```

**Response:**
```json
[
    {
        "ip": "127.0.0.1",
        "hostname": "localhost"
    },
    {
        "ip": "192.168.1.100",
        "hostname": "server1.example.com"
    }
]
```

### 4. Update DNS Record
**PUT** `/dns/{ip}/{hostname}`

Updates an existing DNS record.

**Parameters:**
- `ip`: Current IPv4 address
- `hostname`: Current hostname

**Request Body:**
```json
{
    "ip": "192.168.1.200",
    "hostname": "server1.example.com"
}
```

**Response:**
```json
[
    {
        "ip": "127.0.0.1",
        "hostname": "localhost"
    },
    {
        "ip": "192.168.1.200",
        "hostname": "server1.example.com"
    }
]
```

### 5. Delete DNS Record
**DELETE** `/dns/{ip}/{hostname}`

Deletes a DNS record.

**Parameters:**
- `ip`: IPv4 address to delete
- `hostname`: Hostname to delete

**Response:**
```json
[
    {
        "ip": "127.0.0.1",
        "hostname": "localhost"
    }
]
```

## Validation Rules

### IP Address Validation
- Must be a valid IPv4 address
- Uses the `ipaddress` Python module for validation
- Supports standard IPv4 notation (e.g., `192.168.1.100`)

### Hostname Validation
- Length must be between 1 and 63 characters
- Can contain letters (a-z, A-Z), numbers (0-9), and hyphens
- Cannot start or end with a hyphen
- Must follow RFC 1123 hostname standards
- Case-insensitive validation

**Valid Hostname Examples:**
- `server1.example.com`
- `web-server`
- `api-v1`
- `test123`
- `a` (single character hostnames are valid)

**Invalid Hostname Examples:**
- `-server` (starts with hyphen)
- `server-` (ends with hyphen)
- `server@example.com` (invalid character)
- `` (empty string)

## File Management

### `/etc/hosts` File Handling
- **File Locking**: Uses file locking to prevent concurrent modifications
- **Automatic Creation**: Creates `/etc/hosts` if it doesn't exist
- **Comment Preservation**: Preserves existing comments in the file
- **Sorting**: Automatically sorts records by IP address and hostname
- **Safe Operations**: Thread-safe file operations with proper error handling

### File Format
The API maintains the standard `/etc/hosts` format:

```
127.0.0.1       localhost
192.168.1.100   server1.example.com
192.168.1.101   server2.example.com
```

### dnsmasq Integration
- **Automatic Reload**: Sends SIGHUP to dnsmasq after changes
- **Immediate Effect**: DNS changes take effect immediately
- **Service Integration**: Works with dnsmasq DNS server

## Error Handling

The API provides comprehensive error handling with appropriate HTTP status codes:

- **400 Bad Request**: Invalid input (IP address, hostname format)
- **404 Not Found**: DNS record doesn't exist
- **406 Not Acceptable**: DNS record already exists (for create operations)
- **500 Internal Server Error**: System errors (file operations, dnsmasq)

### Common Error Scenarios

1. **Invalid IP Address**: IP address format is incorrect
2. **Invalid Hostname**: Hostname doesn't meet RFC 1123 standards
3. **Duplicate Record**: Attempting to create a record that already exists
4. **Record Not Found**: Attempting to update/delete a non-existent record
5. **File Permission Error**: Insufficient permissions to modify `/etc/hosts`

### Error Response Format
```json
{
    "detail": "DNS record already present: ip=192.168.1.100, hostname=server1.example.com"
}
```

All exceptions are properly chained using `raise ... from e` for better debugging and traceback information.

## Example Usage

### Adding DNS Records
```bash
# Add a new DNS record
curl -X POST "http://localhost:8000/dns" \
     -H "access_token: your_api_key" \
     -H "Content-Type: application/json" \
     -d '{
         "ip": "192.168.1.100",
         "hostname": "server1.example.com"
     }'
```

### Listing All DNS Records
```bash
curl -X GET "http://localhost:8000/dns" \
     -H "access_token: your_api_key"
```

### Updating a DNS Record
```bash
curl -X PUT "http://localhost:8000/dns/192.168.1.100/server1.example.com" \
     -H "access_token: your_api_key" \
     -H "Content-Type: application/json" \
     -d '{
         "ip": "192.168.1.200",
         "hostname": "server1.example.com"
     }'
```

### Deleting a DNS Record
```bash
curl -X DELETE "http://localhost:8000/dns/192.168.1.100/server1.example.com" \
     -H "access_token: your_api_key"
```

## Security Considerations

- All endpoints require API key authentication
- File locking prevents concurrent modifications to `/etc/hosts`
- Proper validation of all inputs
- Safe file operations with error handling
- Automatic dnsmasq integration for immediate DNS updates

## Performance Considerations

- **File Locking**: Minimal impact with short lock times
- **Efficient Parsing**: Optimized file parsing and sorting
- **Batch Operations**: Single file write per operation
- **dnsmasq Reload**: Fast SIGHUP signal to reload configuration

## Integration with dnsmasq

The DNS management system is designed to work seamlessly with dnsmasq:

1. **Automatic Configuration**: Changes to `/etc/hosts` are automatically detected
2. **Immediate Reload**: SIGHUP signal ensures immediate DNS updates
3. **Service Compatibility**: Works with standard dnsmasq installations
4. **No Manual Intervention**: No need to manually restart dnsmasq

### dnsmasq Configuration
Ensure dnsmasq is configured to read from `/etc/hosts`:

```bash
# In dnsmasq.conf
no-hosts
addn-hosts=/etc/hosts
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the API has write access to `/etc/hosts`
2. **dnsmasq Not Reloading**: Check if dnsmasq is running and accessible
3. **Invalid Hostname**: Verify hostname follows RFC 1123 standards
4. **File Locked**: Wait for other operations to complete

### Debugging

- Check API logs for detailed error messages
- Verify `/etc/hosts` file permissions and ownership
- Test dnsmasq configuration manually
- Check system logs for dnsmasq errors

### Verification Commands

```bash
# Check current DNS records
cat /etc/hosts

# Test DNS resolution
nslookup server1.example.com

# Check dnsmasq status
systemctl status dnsmasq

# Verify file permissions
ls -la /etc/hosts
```

## Best Practices

### DNS Record Management
- Use descriptive hostnames that follow naming conventions
- Keep IP addresses organized and documented
- Regularly review and clean up unused DNS records
- Use consistent naming patterns across your infrastructure

### API Usage
- Always validate input data before sending to API
- Implement proper error handling in client applications
- Use appropriate HTTP status codes for different scenarios
- Monitor API responses for successful operations

### Security
- Use strong API keys and rotate them regularly
- Restrict API access to trusted networks
- Monitor API usage for suspicious activity
- Keep the system updated with security patches

## Future Enhancements

### Potential Improvements
1. **Bulk Operations**: Support for adding multiple DNS records at once
2. **DNS Zones**: Support for different DNS zones or domains
3. **TTL Support**: Configurable TTL values for DNS records
4. **DNS Monitoring**: Real-time DNS resolution monitoring
5. **Web UI**: Graphical interface for DNS management

### Extensibility
The modular design allows for easy extension:
- Additional DNS record types (AAAA, CNAME, etc.)
- Integration with other DNS servers
- Custom validation rules
- Advanced DNS features