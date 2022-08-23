package envoy.authz

test_user {
    allow with input as {
    "attributes": {
      "request": {
        "http": {
          "method": "GET",
          "path": "/user/hello",
          "headers": {
            "authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzYTZza3ZzbE9PM1MycEppZ3gwWWZZR2F6NGxDNThhanREeWg2RWdFWTJvIn0.eyJleHAiOjE2NjA4OTYyMDYsImlhdCI6MTY2MDg5MjYwNiwianRpIjoiODg1MGFhNTgtMWE5NS00NWQ4LTliN2MtNzI5NTk0NTNjN2Q1IiwiaXNzIjoiaHR0cDovLzEwLjIwMC4xMC4xOjgwODAvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI2MDIxNzc2Zi0yODI2LTQyMDktYTVmZC1iMjIzNjNjYmZjMTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJvcGEtc2VjLWRlbW8iLCJzZXNzaW9uX3N0YXRlIjoiOThjNDI5ZjgtOTA1Ni00ZWE2LWEzOTYtY2NjNDljZGQyNTdlIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsib3BhLXNlYy1kZW1vIjp7InJvbGVzIjpbImFwcC11c2VyIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJzaWQiOiI5OGM0MjlmOC05MDU2LTRlYTYtYTM5Ni1jY2M0OWNkZDI1N2UiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImhhaXRhbyJ9.mxly1t5WsVQkwVhIlydjuP8rvHm44VFSdmhsNPT1MehwzBmdpJnNluVcMSnUSWwzrtJem1pObdVRkMY8C9MDcpcB0LB0xkDUhwLt9nPCJuZgZR-4Jv8xh-Jmtz0Z5uDULR3WT6C0TrX_vVWeQvYlcbE-A7i-9GiTiB1tfvax1tP93r2S-4Vu6o--oHNqvwcHBPuPoHGXZXTpV784v6ZJzCRCuRIn5Vr3Y5efc8_e90bc_pGbaCnDNdoxZOASxljBw-ZaKJddIqhHpJDax2cSJA4faTPu-PwspzWM3zBW8qDAk_rHlj0SNzGUR543fyww0xgF7Fjol_H5qujqZF-38Q"
          }
        }
      }
    }
  }
}


test_admin {
    allow with input as {
    "attributes": {
      "request": {
        "http": {
          "method": "GET",
          "path": "/admin/hello",
          "headers": {
            "authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzYTZza3ZzbE9PM1MycEppZ3gwWWZZR2F6NGxDNThhanREeWg2RWdFWTJvIn0.eyJleHAiOjE2NjA4OTYyMDYsImlhdCI6MTY2MDg5MjYwNiwianRpIjoiODg1MGFhNTgtMWE5NS00NWQ4LTliN2MtNzI5NTk0NTNjN2Q1IiwiaXNzIjoiaHR0cDovLzEwLjIwMC4xMC4xOjgwODAvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI2MDIxNzc2Zi0yODI2LTQyMDktYTVmZC1iMjIzNjNjYmZjMTgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJvcGEtc2VjLWRlbW8iLCJzZXNzaW9uX3N0YXRlIjoiOThjNDI5ZjgtOTA1Ni00ZWE2LWEzOTYtY2NjNDljZGQyNTdlIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsib3BhLXNlYy1kZW1vIjp7InJvbGVzIjpbImFwcC11c2VyIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJzaWQiOiI5OGM0MjlmOC05MDU2LTRlYTYtYTM5Ni1jY2M0OWNkZDI1N2UiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImhhaXRhbyJ9.mxly1t5WsVQkwVhIlydjuP8rvHm44VFSdmhsNPT1MehwzBmdpJnNluVcMSnUSWwzrtJem1pObdVRkMY8C9MDcpcB0LB0xkDUhwLt9nPCJuZgZR-4Jv8xh-Jmtz0Z5uDULR3WT6C0TrX_vVWeQvYlcbE-A7i-9GiTiB1tfvax1tP93r2S-4Vu6o--oHNqvwcHBPuPoHGXZXTpV784v6ZJzCRCuRIn5Vr3Y5efc8_e90bc_pGbaCnDNdoxZOASxljBw-ZaKJddIqhHpJDax2cSJA4faTPu-PwspzWM3zBW8qDAk_rHlj0SNzGUR543fyww0xgF7Fjol_H5qujqZF-38Q"
          }
        }
      }
    }
  }
}
