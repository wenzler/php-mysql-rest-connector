# php-mysql-rest-connector

This API supports GET, POST, DELETE and PUT operations.
To access specific tables/views go to e.g. /api/v2//tablename

GET parameters supported:
```
        	&columnname=value
        	&QUERY_LIMIT=integerlimit
        	&QUERY_CONDITION=[OR|AND] default is AND; can only be used once
        	&QUERY_ORDERBYASC=columnname OR &QUERY_ORDERBYDESC=columnname (single use only)
        	&QUERY_ENABLE_EXT_COMPARISON enables extra comparison operators:
                    &columnname=~value using LIKE ( % need to be url encoded as %25 )
                    &columnname=!value using <>
                    &columnname=>value using > 
                    &columnname=<value using <
        
```
POST/PUT expects json encoded data via php://input
```
                curl -u $USER -i -X PUT -H "Content-Type:application/json" https://localhost/api/v2//tablename/id -d '{"field1":1,"field2":"data"}'
                curl -u $USER -i -X POST -H "Content-Type:application/json" https://localhost/api/v2//tablename -d '{"field1":1,"field2":"data"}'
```       

DELETE parameters supported:
```
                curl -u $USER -i -X DELETE https://localhost/api/v2//tablename/id
```       

Response codes:
```
                200: Everything went fine.
                201: Entry created.
                202: Job created for processing.
                204: Query has no results returned.
                400: You sent a request Monitor didn't understand. Correct the input and try again.
                401: You're not authenticated.
                403: You're not authorized to do this.
                404: The URI doesn't exist.
```         
