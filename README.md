# Async Friendly Functions: Asynchronous Way

The `Asynchronous Way` is a small Fast-API authentication app that implements synchronous password hashing.
We will use it to solve the task `Implement async-friendly password hashing` from the `Async Friendly Functions` 
project.

## 1. Running the Application Locally

```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

## 2. Password Hashing Function

The password hashing function can be found at `api/apps/auth/passwords.py`

## 3. Endpoints

This is a standard Fast-API application hence the edpoints can be found at the `/docs` endpoint.

User registration endpoint: POST: `/api/register/`
Health endpoint: GET: `/api/health/`

## 4. Assignments
1) Implement an async-friendly version of the `hash_password` function using `asyncio.to_thread` to offload the blocking bcrypt call to a thread pool. [+]
2) Utilize the synchronous `hash_password` function in the `/api/users/register` endpoint with the async-friendly version.
3) Measure user registration endpoint response time. [-]
4) Measure health-check endpoint response time. [-]
5) Measure registration endpoint response time when registration requests are running concurrently. Execute the experiment with 10, 100, 1000 concurrent requests. [-]
6) Measure `health` endpoint response time when running concurrently with the registration requests. [-]
7) Analyze the results: [-]
    - how responsiveness is affected under load?
    - how does the health-check endpoint behave when multiple registration requests are running concurrently? How does its response time change with concurrency?
    - how does the average response time of registration end-point change with concurrency?
8) Measure CPU and memory usage during the experiments. [-]
9) Compare the results with the results in the `Observe blocking behavior` section. 
10) Describe improvements in latency, concurrency, and responsiveness. 
11) Note any unexpected behaviors or challenges encountered.

## 5. Solution

### 5.1. Password Hashing Function

- The asynchronous password hashing function `hash_password` is located at `api/apps/auth/passwords.py`. This function is used in the user registration endpoint to hash the user's password before storing it.

- There is also the asynchronous password verification function `verify_password` that is used to verify the user's password during login. It is located at the same file `api/apps/auth/passwords.py`.

### 5.2. Endpoints

- User registration endpoint is implemented at `/api/users/register/`

- API health-check endpoint is implemented at `/api/health/`

The user registration endpoint uses the asynchronous `hash_password` function to hash the user's password.

### 5.3. Measuring the Response times of the `/api/users/register/` and `/api/health/` Endpoints

#### 5.3.1 Introduction

We will apply the same measurements strategy as in the  [synchronous-block project](https://github.com/alv2017/synchronous-block).

1) We will use server side logging middleware to measure the response times of the endpoints. We will also be measuring the response time on the client side.
2) In order to measure the response time of a single endpoint we will send 100 consecutive requests to the endpoint and calculate the average response time.
3) For server side logging we will be using the `asgi-logging-middleware` package, this is not obligatory, and you can use whatever you like.

#### 5.3.2 Setting up the `asgi-logging-middleware`

1) We need to install the `asgi-logging-middleware` package:

```bash
pip install asgi-logging-middleware
```

2) We will add a separate performance logger, and use it with the `AccessLoggerMiddleware`. The logger is located 
at `api/loggers/performance_logger.py`.

3) We need to add the `AccessLoggerMiddleware` middleware to the Fast-API application. To do that we need to modify the 
`api/main.py`. The modification have been done following the FastAPI documentation on adding ASGI middleware ([Adding ASGI Middlewares](https://fastapi.tiangolo.com/advanced/middleware/#adding-asgi-middlewares))  and the documentation of[asgi-logging-middleware](https://github.com/alv2017/asgi-logging-middleware) package. 

#### 5.3.3 Measuring the Response time of the `/api/health/` Endpoint

We will create our own script that sends 100 consecutive requests to the `/api/health/` endpoint. Then we will parse the performance log file and calculate the average response time.

Our script that sends requests to the endpoint can also measure the response time, this time on the client's side, hence we will be able to compare the server side response time with the client side response time!

The scripts are identical to the scripts in [synchronous-block project](https://github.com/alv2017/synchronous-block).

Script location: `measurements/response_times/api_health_endpoint/response_time.py`

Server log results: `measurements/response_times/api_health_endpoint/api_health_performance.log`

**Results:**

1) Server side average response time for `/api/health/` endpoint: 0.3616 ms 
2) Client side average response time for `/api/health/` endpoint: 1.5450 ms

#### 5.3.4 Measuring the Response Time of the `/api/users/register/` Endpoint

Script location: `measurements/response_times/api_register_endpoint/response_time.py`

Server log results: `measurements/response_times/api_register_endpoint/api_health_performance.log`

The scripts are identical to the scripts in [synchronous-block project](https://github.com/alv2017/synchronous-block).

**Results:**

1) Server side average response time for `/api/user/register/` endpoint: 218.0159 ms
2) Client side average response time for `/api/user/register` endpoint: 219.6050 ms