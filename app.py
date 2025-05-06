from aiohttp import web


async def handle_form(request: web.Request) -> web.Response:
    """Handle a standard multipart/form-data POST."""
    data = await request.post()  # vulnerable to CVE-2024-30251 in aiohttp < 3.9.4
    name = data.get("name", "anonymous")
    return web.Response(text=f"Hello, {name}!")


async def handle_injected_header(request: web.Request) -> web.Response:
    """
    Responds with a header that simulates CRLF injection, triggering
    response splitting vulnerability (CVE-2023-27522) in uWSGI < 2.0.22.
    """
    response = web.Response(text="This response contains an injected header.")
    # CRLF injection to simulate smuggled header:
    response.headers["X-Injection"] = "value\r\nInjected-Header: evil"
    return response


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/upload", handle_form)
    app.router.add_get("/inject", handle_injected_header)
    return app


def main() -> None:
    app = create_app()
    web.run_app(app, port=8080)


if __name__ == "__main__":
    main()
