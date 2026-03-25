export default function middleware(request: Request) {
  const username = process.env.MCN_BASIC_AUTH_USER;
  const password = process.env.MCN_BASIC_AUTH_PASSWORD;

  if (!username || !password) {
    return new Response(
      "Missing MCN_BASIC_AUTH_USER or MCN_BASIC_AUTH_PASSWORD environment variables.",
      { status: 500 }
    );
  }

  const authHeader = request.headers.get("authorization");

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return new Response("Authentication required.", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="MCN Members", charset="UTF-8"',
        "Cache-Control": "no-store",
      },
    });
  }

  const base64Credentials = authHeader.split(" ")[1];
  const decoded = atob(base64Credentials);
  const separatorIndex = decoded.indexOf(":");

  if (separatorIndex === -1) {
    return new Response("Authentication required.", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="MCN Members", charset="UTF-8"',
        "Cache-Control": "no-store",
      },
    });
  }

  const providedUser = decoded.slice(0, separatorIndex);
  const providedPassword = decoded.slice(separatorIndex + 1);

  if (providedUser !== username || providedPassword !== password) {
    return new Response("Authentication required.", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="MCN Members", charset="UTF-8"',
        "Cache-Control": "no-store",
      },
    });
  }

  return;
}

export const config = {
  matcher: ["/protected/:path*"],
};
