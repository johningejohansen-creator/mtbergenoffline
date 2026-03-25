import { NextRequest, NextResponse } from 'next/server'

function unauthorizedResponse() {
  return new NextResponse('Authentication required.', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="MCN Members", charset="UTF-8"',
      'Cache-Control': 'no-store',
    },
  })
}

export function middleware(request: NextRequest) {
  const username = process.env.MCN_BASIC_AUTH_USER
  const password = process.env.MCN_BASIC_AUTH_PASSWORD

  if (!username || !password) {
    return new NextResponse(
      'Missing MCN_BASIC_AUTH_USER or MCN_BASIC_AUTH_PASSWORD environment variables.',
      { status: 500 }
    )
  }

  const authHeader = request.headers.get('authorization')

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return unauthorizedResponse()
  }

  const base64Credentials = authHeader.split(' ')[1]
  const decoded = atob(base64Credentials)
  const separatorIndex = decoded.indexOf(':')

  if (separatorIndex === -1) {
    return unauthorizedResponse()
  }

  const providedUser = decoded.slice(0, separatorIndex)
  const providedPassword = decoded.slice(separatorIndex + 1)

  if (providedUser !== username || providedPassword !== password) {
    return unauthorizedResponse()
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/protected/:path*'],
}
