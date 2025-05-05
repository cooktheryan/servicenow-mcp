"""
ServiceNow MCP Server

This module provides a Model Context Protocol (MCP) server that interfaces with ServiceNow.
It allows AI agents to access and manipulate ServiceNow data through a secure API.
"""

import os
import json
import asyncio
import logging
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Literal

import requests
import httpx
from pydantic import BaseModel, Field, field_validator

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)

# ServiceNow API models
class IncidentState(int, Enum):
    NEW = 1
    IN_PROGRESS = 2 
    ON_HOLD = 3
    RESOLVED = 6
    CLOSED = 7
    CANCELED = 8

class IncidentPriority(int, Enum):
    CRITICAL = 1
    HIGH = 2
    MODERATE = 3
    LOW = 4
    PLANNING = 5

class IncidentUrgency(int, Enum):
    HIGH = 1
    MEDIUM = 2
    LOW = 3

class IncidentImpact(int, Enum):
    HIGH = 1
    MEDIUM = 2
    LOW = 3

class IncidentCreate(BaseModel):
    """Model for creating a new incident"""
    short_description: str = Field(..., description="A brief description of the incident")
    description: str = Field(..., description="A detailed description of the incident")
    caller_id: Optional[str] = Field(None, description="The sys_id or name of the caller")
    category: Optional[str] = Field(None, description="The incident category")
    subcategory: Optional[str] = Field(None, description="The incident subcategory")
    urgency: Optional[IncidentUrgency] = Field(IncidentUrgency.MEDIUM, description="The urgency of the incident")
    impact: Optional[IncidentImpact] = Field(IncidentImpact.MEDIUM, description="The impact of the incident")
    assignment_group: Optional[str] = Field(None, description="The sys_id or name of the assignment group")
    assigned_to: Optional[str] = Field(None, description="The sys_id or name of the assignee")

class IncidentUpdate(BaseModel):
    """Model for updating an existing incident"""
    short_description: Optional[str] = Field(None, description="A brief description of the incident")
    description: Optional[str] = Field(None, description="A detailed description of the incident")
    caller_id: Optional[str] = Field(None, description="The sys_id or name of the caller")
    category: Optional[str] = Field(None, description="The incident category")
    subcategory: Optional[str] = Field(None, description="The incident subcategory")
    urgency: Optional[IncidentUrgency] = Field(None, description="The urgency of the incident")
    impact: Optional[IncidentImpact] = Field(None, description="The impact of the incident")
    state: Optional[IncidentState] = Field(None, description="The state of the incident")
    assignment_group: Optional[str] = Field(None, description="The sys_id or name of the assignment group")
    assigned_to: Optional[str] = Field(None, description="The sys_id or name of the assignee")
    work_notes: Optional[str] = Field(None, description="Work notes to add to the incident (internal)")
    comments: Optional[str] = Field(None, description="Customer visible comments to add to the incident")
    
    @field_validator('work_notes', 'comments')
    @classmethod
    def validate_not_empty(cls, v):
        if v is not None and v.strip() == '':
            raise ValueError("Cannot be an empty string")
        return v

    class Config:
        use_enum_values = True
        
class QueryOptions(BaseModel):
    """Options for querying ServiceNow records"""
    limit: int = Field(10, description="Maximum number of records to return", ge=1, le=1000)
    offset: int = Field(0, description="Number of records to skip", ge=0)
    fields: Optional[List[str]] = Field(None, description="List of fields to return")
    query: Optional[str] = Field(None, description="ServiceNow encoded query string")
    order_by: Optional[str] = Field(None, description="Field to order results by")
    order_direction: Optional[Literal["asc", "desc"]] = Field("desc", description="Order direction")

class Authentication:
    """Base class for ServiceNow authentication methods"""
    
    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for ServiceNow API requests"""
        raise NotImplementedError("Subclasses must implement this method")

class BasicAuth(Authentication):
    """Basic authentication for ServiceNow"""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        
    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for ServiceNow API requests"""
        return {}
    
    def get_auth(self) -> tuple:
        """Get authentication tuple for requests"""
        return (self.username, self.password)

class TokenAuth(Authentication):
    """Token authentication for ServiceNow"""
    
    def __init__(self, token: str):
        self.token = token
        
    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for ServiceNow API requests"""
        return {"Authorization": f"Bearer {self.token}"}
    
    def get_auth(self) -> None:
        """Get authentication tuple for requests"""
        return None

class OAuthAuth(Authentication):
    """OAuth authentication for ServiceNow"""
    
    def __init__(self, client_id: str, client_secret: str, username: str, password: str, 
                 instance_url: str, token: Optional[str] = None, refresh_token: Optional[str] = None,
                 token_expiry: Optional[datetime] = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.instance_url = instance_url
        self.token = token
        self.refresh_token = refresh_token
        self.token_expiry = token_expiry
        
    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for ServiceNow API requests"""
        if self.token is None or (self.token_expiry and datetime.now() > self.token_expiry):
            await self.refresh()
            
        return {"Authorization": f"Bearer {self.token}"}
    
    def get_auth(self) -> None:
        """Get authentication tuple for requests"""
        return None
        
    async def refresh(self):
        """Refresh the OAuth token"""
        if self.refresh_token:
            # Try refresh flow first
            data = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token
            }
        else:
            # Fall back to password flow
            data = {
                "grant_type": "password",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "username": self.username,
                "password": self.password
            }
            
        token_url = f"{self.instance_url}/oauth_token.do"
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            result = response.json()
            
            self.token = result["access_token"]
            self.refresh_token = result.get("refresh_token")
            expires_in = result.get("expires_in", 1800)  # Default 30 minutes
            self.token_expiry = datetime.now().timestamp() + expires_in

class ServiceNowClient:
    """Client for interacting with ServiceNow API"""
    
    def __init__(self, instance_url: str, auth: Authentication):
        self.instance_url = instance_url.rstrip('/')
        self.auth = auth
        self.client = httpx.AsyncClient()
        
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
        
    async def request(self, method: str, path: str, 
                    params: Optional[Dict[str, Any]] = None,
                    json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a request to the ServiceNow API"""
        url = f"{self.instance_url}{path}"
        headers = await self.auth.get_headers()
        headers["Accept"] = "application/json"
        
        if isinstance(self.auth, BasicAuth):
            auth = self.auth.get_auth()
        else:
            auth = None
            
        try:
            response = await self.client.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=headers,
                auth=auth
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"ServiceNow API error: {e.response.text}")
            raise
            
    async def get_record(self, table: str, sys_id: str) -> Dict[str, Any]:
        """Get a record by sys_id"""
        return await self.request("GET", f"/api/now/table/{table}/{sys_id}")
        
    async def get_records(self, table: str, options: QueryOptions = None) -> Dict[str, Any]:
        """Get records with query options"""
        if options is None:
            options = QueryOptions()
            
        params = {
            "sysparm_limit": options.limit,
            "sysparm_offset": options.offset
        }
        
        if options.fields:
            params["sysparm_fields"] = ",".join(options.fields)
            
        if options.query:
            params["sysparm_query"] = options.query
            
        if options.order_by:
            direction = "desc" if options.order_direction == "desc" else "asc"
            params["sysparm_order_by"] = f"{options.order_by}^{direction}"
            
        return await self.request("GET", f"/api/now/table/{table}", params=params)
    
    async def create_record(self, table: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new record"""
        return await self.request("POST", f"/api/now/table/{table}", json_data=data)
        
    async def update_record(self, table: str, sys_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing record"""
        return await self.request("PUT", f"/api/now/table/{table}/{sys_id}", json_data=data)
        
    async def delete_record(self, table: str, sys_id: str) -> Dict[str, Any]:
        """Delete a record"""
        return await self.request("DELETE", f"/api/now/table/{table}/{sys_id}")
        
    async def get_incident_by_number(self, number: str) -> Dict[str, Any]:
        """Get an incident by its number"""
        result = await self.request("GET", f"/api/now/table/incident", 
                                  params={"sysparm_query": f"number={number}", "sysparm_limit": 1})
        if result.get("result") and len(result["result"]) > 0:
            return result["result"][0]
        return None
        
    async def search(self, query: str, table: str = "incident", limit: int = 10) -> Dict[str, Any]:
        """Search for records using text query"""
        return await self.request("GET", f"/api/now/table/{table}", 
                                params={"sysparm_query": f"123TEXTQUERY321={query}", "sysparm_limit": limit})
                                
    async def get_available_tables(self) -> List[str]:
        """Get a list of available tables"""
        result = await self.request("GET", "/api/now/table/sys_db_object", 
                                  params={"sysparm_fields": "name,label", "sysparm_limit": 100})
        return result.get("result", [])
        
    async def get_table_schema(self, table: str) -> Dict[str, Any]:
        """Get the schema for a table"""
        result = await self.request("GET", f"/api/now/ui/meta/{table}")
        return result


class ServiceNowMCP:
    """ServiceNow MCP Server"""
    
    def __init__(self, 
                instance_url: str,
                auth: Authentication,
                name: str = "ServiceNow MCP"):
        self.client = ServiceNowClient(instance_url, auth)
        self.mcp = FastMCP(name, dependencies=[
            "requests",
            "httpx", 
            "pydantic"
        ])
        
        # Register resources
        self.mcp.resource("servicenow://incidents")(self.list_incidents)
        self.mcp.resource("servicenow://incidents/{number}")(self.get_incident)
        self.mcp.resource("servicenow://users")(self.list_users)
        self.mcp.resource("servicenow://knowledge")(self.list_knowledge)
        self.mcp.resource("servicenow://tables")(self.get_tables)
        self.mcp.resource("servicenow://tables/{table}")(self.get_table_records)
        self.mcp.resource("servicenow://schema/{table}")(self.get_table_schema)
        
        # Register tools
        self.mcp.tool(name="create_incident")(self.create_incident)
        self.mcp.tool(name="get_record")(self.get_record)
        
        # Register prompts
        self.mcp.prompt(name="analyze_incident")(self.incident_analysis_prompt)
        self.mcp.prompt(name="create_incident_prompt")(self.create_incident_prompt)
    
    async def close(self):
        """Close the ServiceNow client"""
        await self.client.close()
        
    def run(self, transport: str = "stdio"):
        """Run the ServiceNow MCP server"""
        try:
            self.mcp.run(transport=transport)
        finally:
            asyncio.run(self.close())
        
    # Resource handlers
    async def list_incidents(self) -> str:
        """List recent incidents in ServiceNow"""
        options = QueryOptions(limit=10)
        result = await self.client.get_records("incident", options)
        return json.dumps(result, indent=2)
        
    async def get_incident(self, number: str) -> str:
        """Get a specific incident by number"""
        try:
            # Always use get_incident_by_number to query by incident number, not get_record
            incident = await self.client.get_incident_by_number(number)
            if incident:
                # Use the formatter for consistent output
                return self._format_incident_record(incident)
            else:
                logger.error(f"No incident found with number: {number}")
                return json.dumps({"error":{"message":"No Record found","detail":"Record doesn't exist or ACL restricts the record retrieval"},"status":"failure"}, indent=2)
        except Exception as e:
            logger.error(f"Error getting incident {number}: {str(e)}")
            return json.dumps({"error":{"message":str(e),"detail":"Error occurred while retrieving the record"},"status":"failure"}, indent=2)
        
    async def list_users(self) -> str:
        """List users in ServiceNow"""
        options = QueryOptions(limit=10)
        result = await self.client.get_records("sys_user", options)
        return json.dumps(result, indent=2)
        
    async def list_knowledge(self) -> str:
        """List knowledge articles in ServiceNow"""
        options = QueryOptions(limit=10)
        result = await self.client.get_records("kb_knowledge", options)
        return json.dumps(result, indent=2)
        
    async def get_tables(self) -> str:
        """Get a list of available tables"""
        result = await self.client.get_available_tables()
        return json.dumps({"result": result}, indent=2)
        
    async def get_table_records(self, table: str) -> str:
        """Get records from a specific table"""
        options = QueryOptions(limit=10)
        result = await self.client.get_records(table, options)
        return json.dumps(result, indent=2)
        
    async def get_table_schema(self, table: str) -> str:
        """Get the schema for a table"""
        result = await self.client.get_table_schema(table)
        return json.dumps(result, indent=2)
    
    # Tool handlers
    async def create_incident(self, 
                     incident,
                     ctx: Context = None) -> str:
        """
        Create a new incident in ServiceNow
        
        Args:
            incident: The incident details to create - must be a dictionary containing incident fields
                     with at least short_description and description
            ctx: Optional context object for progress reporting
        
        Returns:
            JSON response from ServiceNow with human-readable formatting
        """
        # Handle input - ensure it's a dictionary
        if isinstance(incident, dict):
            incident_data = incident
            logger.info(f"Creating incident from dictionary: {incident.get('short_description', 'No short description')}")
        elif isinstance(incident, IncidentCreate):
            # IncidentCreate model provided
            incident_data = incident.dict(exclude_none=True)
            logger.info(f"Creating incident from IncidentCreate: {incident.short_description}")
        else:
            error_message = f"Invalid incident type: {type(incident)}. Expected dictionary or IncidentCreate."
            logger.error(error_message)
            return json.dumps({"error": error_message}, indent=2)

        # Validate that required fields are present
        if "short_description" not in incident_data:
            if "description" in incident_data:
                # Auto-generate short description from description
                desc = incident_data["description"]
                incident_data["short_description"] = desc[:50] + ('...' if len(desc) > 50 else '')
            else:
                incident_data["short_description"] = "Incident created through API"
        
        if "description" not in incident_data:
            if "short_description" in incident_data:
                incident_data["description"] = incident_data["short_description"]
            else:
                incident_data["description"] = "No description provided"
    
        # Log and create the incident
        if ctx:
            await ctx.info(f"Creating incident: {incident_data.get('short_description', 'No short description')}")
        
        try:
            result = await self.client.create_record("incident", incident_data)
            incident_result = result.get('result', {})
            
            # Create a human-readable response
            incident_number = incident_result.get('number', 'Unknown')
            description = incident_result.get('description', 'No description provided')
            created_by = incident_result.get('sys_created_by', 'Unknown')
            created_on = incident_result.get('sys_created_on', 'Unknown')
            status = self._get_state_label(incident_result.get('state', 'Unknown'))
            priority = incident_result.get('priority', 'Unknown')
            impact = incident_result.get('impact', 'Unknown')
            category = incident_result.get('category', 'Unknown') or 'Uncategorized'
            assigned_to = incident_result.get('assigned_to', {}).get('display_value', 'Unassigned')
            assignment_group = incident_result.get('assignment_group', {}).get('display_value', 'Unassigned')
            
            # Format priority and impact for readability
            priority_map = {1: "1 (Critical)", 2: "2 (High)", 3: "3 (Moderate)", 4: "4 (Low)", 5: "5 (Planning)"}
            impact_map = {1: "1 (High)", 2: "2 (Medium)", 3: "3 (Low)"}
            
            priority_str = priority_map.get(priority, str(priority))
            impact_str = impact_map.get(impact, str(impact))
            
            # Build the human-readable response
            human_readable = {
                "message": f"The incident \"{incident_data.get('short_description', 'No short description')}\" has been created in ServiceNow with the following details:",
                "details": {
                    "incident_number": incident_number,
                    "description": description,
                    "created_by": created_by,
                    "created_on": created_on,
                    "status": status,
                    "priority": priority_str,
                    "impact": impact_str,
                    "category": category,
                    "assigned_to": assigned_to,
                    "assignment_group": assignment_group
                },
                "raw_response": result
            }
            
            if ctx:
                await ctx.info(f"Created incident: {incident_number}")
                
            return json.dumps(human_readable, indent=2)
        except Exception as e:
            error_message = f"Error creating incident: {str(e)}"
            logger.error(error_message)
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message}, indent=2)
            
    def _get_state_label(self, state):
        """Get a human-readable label for an incident state"""
        state_map = {
            "1": "New",
            "2": "In Progress",
            "3": "On Hold",
            "6": "Resolved",
            "7": "Closed",
            "8": "Canceled"
        }
        return state_map.get(str(state), f"Unknown ({state})")
        
    async def update_incident(self,
                     number: str,
                     updates: IncidentUpdate,
                     ctx: Context = None) -> str:
        """
        Update an existing incident in ServiceNow
        
        Args:
            number: The incident number (INC0010001)
            updates: The fields to update
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response from ServiceNow
        """
        # First, get the sys_id for the incident number
        if ctx:
            await ctx.info(f"Looking up incident: {number}")
            
        incident = await self.client.get_incident_by_number(number)
        
        if not incident:
            error_message = f"Incident {number} not found"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})
            
        sys_id = incident['sys_id']
        
        # Now update the incident
        if ctx:
            await ctx.info(f"Updating incident: {number}")
            
        data = updates.dict(exclude_none=True)
        result = await self.client.update_record("incident", sys_id, data)
        
        return json.dumps(result, indent=2)
        
    async def search_records(self, 
                    query: str, 
                    table: str = "incident",
                    limit: int = 10,
                    ctx: Context = None) -> str:
        """
        Search for records in ServiceNow using text query
        
        Args:
            query: Text to search for
            table: Table to search in
            limit: Maximum number of results to return
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response containing matching records
        """
        if ctx:
            await ctx.info(f"Searching {table} for: {query}")
            
        result = await self.client.search(query, table, limit)
        return json.dumps(result, indent=2)
        
    async def get_record(self,
                table: str,
                sys_id: str,
                ctx: Context = None) -> str:
        """
        Get a specific record by sys_id
        
        Args:
            table: Table to query
            sys_id: System ID of the record
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response containing the record with human-readable formatting for incidents
        """
        if ctx:
            await ctx.info(f"Getting {table} record: {sys_id}")
        
        # Handle incident numbers passed directly
        if table.lower() == "incident" and sys_id.upper().startswith("INC"):
            try:
                incident = await self.client.get_incident_by_number(sys_id)
                if incident:
                    return self._format_incident_record(incident)
                else:
                    return json.dumps({"error": f"Incident {sys_id} not found"}, indent=2)
            except Exception as e:
                return json.dumps({"error": f"Error retrieving incident: {str(e)}"}, indent=2)
            
        try:    
            result = await self.client.get_record(table, sys_id)
            
            # For incidents, provide a more human-readable format
            if table.lower() == "incident" and "result" in result:
                return self._format_incident_record(result["result"])
            
            return json.dumps(result, indent=2)
        except Exception as e:
            error_message = f"Error retrieving record: {str(e)}"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message}, indent=2)
            
    def _format_incident_record(self, incident):
        """Format an incident record for human readability"""
        # Extract key fields
        incident_number = incident.get('number', 'Unknown')
        short_description = incident.get('short_description', 'No short description')
        description = incident.get('description', 'No description provided')
        created_by = incident.get('sys_created_by', 'Unknown')
        created_on = incident.get('sys_created_on', 'Unknown')
        updated_on = incident.get('sys_updated_on', 'Unknown')
        status = self._get_state_label(incident.get('state', 'Unknown'))
        priority = incident.get('priority', 'Unknown')
        impact = incident.get('impact', 'Unknown')
        urgency = incident.get('urgency', 'Unknown')
        category = incident.get('category', 'Unknown') or 'Uncategorized'
        subcategory = incident.get('subcategory', 'Unknown') or 'Uncategorized'
        assigned_to = incident.get('assigned_to', {}).get('display_value', 'Unassigned')
        assignment_group = incident.get('assignment_group', {}).get('display_value', 'Unassigned')
        caller = incident.get('caller_id', {}).get('display_value', 'Unknown')
        
        # Format priority, impact and urgency for readability
        priority_map = {1: "1 (Critical)", 2: "2 (High)", 3: "3 (Moderate)", 4: "4 (Low)", 5: "5 (Planning)"}
        impact_map = {1: "1 (High)", 2: "2 (Medium)", 3: "3 (Low)"}
        urgency_map = {1: "1 (High)", 2: "2 (Medium)", 3: "3 (Low)"}
        
        priority_str = priority_map.get(priority, str(priority))
        impact_str = impact_map.get(impact, str(impact))
        urgency_str = urgency_map.get(urgency, str(urgency))
        
        # Build the human-readable response
        human_readable = {
            "message": f"Retrieved incident {incident_number}: {short_description}",
            "details": {
                "incident_number": incident_number,
                "short_description": short_description,
                "description": description,
                "caller": caller,
                "created_by": created_by,
                "created_on": created_on,
                "updated_on": updated_on,
                "status": status,
                "priority": priority_str,
                "impact": impact_str,
                "urgency": urgency_str,
                "category": category,
                "subcategory": subcategory,
                "assigned_to": assigned_to,
                "assignment_group": assignment_group
            },
            "raw_record": incident
        }
        
        return json.dumps(human_readable, indent=2)
        
    async def perform_query(self,
                   table: str,
                   query: str = "",
                   limit: int = 10,
                   offset: int = 0,
                   fields: Optional[List[str]] = None,
                   ctx: Context = None) -> str:
        """
        Perform a query against ServiceNow
        
        Args:
            table: Table to query
            query: Encoded query string (ServiceNow syntax)
            limit: Maximum number of results to return
            offset: Number of records to skip
            fields: List of fields to return (or all fields if None)
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response containing query results
        """
        if ctx:
            await ctx.info(f"Querying {table} with: {query}")
            
        options = QueryOptions(
            limit=limit,
            offset=offset,
            fields=fields,
            query=query
        )
        
        result = await self.client.get_records(table, options)
        return json.dumps(result, indent=2)
        
    async def add_comment(self,
                 number: str,
                 comment: str,
                 ctx: Context = None) -> str:
        """
        Add a comment to an incident (customer visible)
        
        Args:
            number: Incident number
            comment: Comment to add
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response from ServiceNow
        """
        if ctx:
            await ctx.info(f"Adding comment to incident: {number}")
            
        incident = await self.client.get_incident_by_number(number)
        
        if not incident:
            error_message = f"Incident {number} not found"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})
            
        sys_id = incident['sys_id']
        
        # Add the comment
        update = {"comments": comment}
        result = await self.client.update_record("incident", sys_id, update)
        
        return json.dumps(result, indent=2)
        
    async def add_work_notes(self,
                    number: str,
                    work_notes: str,
                    ctx: Context = None) -> str:
        """
        Add work notes to an incident (internal)
        
        Args:
            number: Incident number
            work_notes: Work notes to add
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response from ServiceNow
        """
        if ctx:
            await ctx.info(f"Adding work notes to incident: {number}")
            
        incident = await self.client.get_incident_by_number(number)
        
        if not incident:
            error_message = f"Incident {number} not found"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})
            
        sys_id = incident['sys_id']
        
        # Add the work notes
        update = {"work_notes": work_notes}
        result = await self.client.update_record("incident", sys_id, update)
        
        return json.dumps(result, indent=2)
    
    # Prompt templates
    def incident_analysis_prompt(self, incident_number: str) -> str:
        """Create a prompt to analyze a ServiceNow incident
        
        Args:
            incident_number: The incident number to analyze (e.g., INC0010001)
            
        Returns:
            Prompt text for analyzing the incident
        """
        return f"""
        Please analyze the following ServiceNow incident {incident_number}.
        
        First, call the appropriate tool to fetch the incident details using get_incident.
        
        Then, provide a comprehensive analysis with the following sections:
        
        1. Summary: A brief overview of the incident
        2. Impact Assessment: Analysis of the impact based on the severity, priority, and affected users
        3. Root Cause Analysis: Potential causes based on available information
        4. Resolution Recommendations: Suggested next steps to resolve the incident
        5. SLA Status: Whether the incident is at risk of breaching SLAs
        
        Use a professional and clear tone appropriate for IT service management.
        """
        
    def create_incident_prompt(self) -> str:
        """Create a prompt for incident creation guidance
        
        Returns:
            Prompt text for helping users create an incident
        """
        return """
        I'll help you create a new ServiceNow incident. Please provide the following information:
        
        1. Short Description: A brief title for the incident (required)
        2. Detailed Description: A thorough explanation of the issue (required)
        3. Caller: The person reporting the issue (optional)
        4. Category and Subcategory: The type of issue (optional)
        5. Impact (1-High, 2-Medium, 3-Low): How broadly this affects users (optional)
        6. Urgency (1-High, 2-Medium, 3-Low): How time-sensitive this issue is (optional)
        
        After collecting this information, I'll use the create_incident tool to submit the incident to ServiceNow.
        """


# Factory functions for creating authentication objects
def create_basic_auth(username: str, password: str) -> BasicAuth:
    """Create BasicAuth object for ServiceNow authentication"""
    return BasicAuth(username, password)

def create_token_auth(token: str) -> TokenAuth:
    """Create TokenAuth object for ServiceNow authentication"""
    return TokenAuth(token)

def create_oauth_auth(client_id: str, client_secret: str, 
                     username: str, password: str,
                     instance_url: str) -> OAuthAuth:
    """Create OAuthAuth object for ServiceNow authentication"""
    return OAuthAuth(client_id, client_secret, username, password, instance_url)

# Main function for running the server from the command line
def main():
    """Run the ServiceNow MCP server from the command line"""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="ServiceNow MCP Server")
    parser.add_argument("--url", help="ServiceNow instance URL", default=os.environ.get("SERVICENOW_INSTANCE_URL"))
    parser.add_argument("--transport", help="Transport protocol (stdio or sse)", default="stdio", choices=["stdio", "sse"])
    
    # Authentication options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("--username", help="ServiceNow username", default=os.environ.get("SERVICENOW_USERNAME"))
    auth_group.add_argument("--password", help="ServiceNow password", default=os.environ.get("SERVICENOW_PASSWORD"))
    auth_group.add_argument("--token", help="ServiceNow token", default=os.environ.get("SERVICENOW_TOKEN"))
    auth_group.add_argument("--client-id", help="OAuth client ID", default=os.environ.get("SERVICENOW_CLIENT_ID"))
    auth_group.add_argument("--client-secret", help="OAuth client secret", default=os.environ.get("SERVICENOW_CLIENT_SECRET"))
    
    args = parser.parse_args()
    
    # Check required parameters
    if not args.url:
        print("Error: ServiceNow instance URL is required")
        print("Set SERVICENOW_INSTANCE_URL environment variable or use --url")
        sys.exit(1)
    
    # Determine authentication method
    auth = None
    if args.token:
        auth = create_token_auth(args.token)
    elif args.client_id and args.client_secret and args.username and args.password:
        auth = create_oauth_auth(args.client_id, args.client_secret, args.username, args.password, args.url)
    elif args.username and args.password:
        auth = create_basic_auth(args.username, args.password)
    else:
        print("Error: Authentication credentials required")
        print("Either provide username/password, token, or OAuth credentials")
        sys.exit(1)
    
    # Create and run the server
    server = ServiceNowMCP(instance_url=args.url, auth=auth)
    server.run(transport=args.transport)

# Entry point
if __name__ == "__main__":
    main()
