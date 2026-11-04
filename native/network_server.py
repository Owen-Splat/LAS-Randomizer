"""Bounded loopback diagnostic server. No Archipelago or item packets."""
import argparse
import socket
import time

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--timeout",type=int,default=180)
    args=p.parse_args()
    with socket.socket() as server:
        server.bind(("127.0.0.1",17779));server.listen(1);server.settimeout(args.timeout)
        print("Listening on loopback 17779",flush=True)
        connection,address=server.accept()
        with connection:
            connection.settimeout(20)
            stream=connection.makefile("rb")
            hello=stream.readline(128)
            if hello!=b"LAS_NATIVE_PROBE_V1\n":raise ValueError(f"Wrong diagnostic hello: {hello!r}")
            print("Native hello received",flush=True)
            connection.sendall(b"PING\n")
            if stream.readline(128)!=b"PONG\n":raise ValueError("PONG not received")
            print("LIVE NATIVE LOOPBACK PING/PONG PASSED",flush=True)
