## Relevant libraries

- Backend
  - Flask: https://flask.palletsprojects.com/en/2.3.x/quickstart/#a-minimal-application
  - UUID: https://docs.python.org/3/library/uuid.html


## Data Formats

### POST "/analyze"
Body:
```json
    {
        "id": string (UUID v4)
        "sample": [number, number, ..., number] // <- array of 12 64-bit integers (additive shares in Z_64 of a fixed point encoding of the data point)
    }
```

Returns:

- **Code 201 (Created)** if computation was started successfully

- **Code 400 (Bad Request)** if request was malformed
```json
    string // detailed error
```

- **Code 500 (Internal Server Error)** if the server cannot start the MP-SPDZ copmutation
```json
    string // detailed error or logfile
```

### GET "/results/\<id\>"
Body: None

`<id>` is a UUID v4 request as string: e.g. 5a2e9c8e-73f2-4abe-ae93-becd164937cb

Returns:

- **Code 200 (OK)** if the computation with `<id>` is present and returns a response of either
    - computation is still running
    
    ```json
    {
        "type": "STILL_RUNNING"
    }
    ```
    
    - computation successfully finished
    
    ```json
    {
        "type": "READY",
        "prediction": [number, ..., number] // array of 64-bit integers (additive shares in Z_64 of a fixed point encoding of the confidence for each class)
    }
    ```
    - computation failed
    
    ```json
    {
        "type": "EXEC_ERROR",
        "details": string // relevant error log
    }
    ```

- **Code 404 (Not Found)** if the computation with `<id>` doesn't exist
