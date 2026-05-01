import { NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import bcrypt from 'bcryptjs'
import { getRealUsers, createUsers } from '@/lib/users';

interface DecodedToken {
  role?: string;
  userId?: string;
  id?: string;
}

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || '');

export async function GET(request: Request): Promise<NextResponse> {

  try {
    const cookieHeader = request.headers.get('cookie') || '';
    const token = cookieHeader.match(/(?:^|; )token=([^;]+)/)?.[1];
    const authToken = cookieHeader.match(/(?:^|; )auth-token=([^;]+)/)?.[1];
    const activeToken = authToken || token;

    if (!activeToken) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const { payload } = await jwtVerify(activeToken, JWT_SECRET);
    const decoded = payload as unknown as DecodedToken;

    if (decoded.role !== 'admin') {
      return NextResponse.json({ error: 'No tienes permisos de administrador' }, { status: 403 });
    }

    const users = await getRealUsers();

    return NextResponse.json(users);

  } catch (error) {
    console.error('Error en /api/admin/users:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}

export async function POST(request: Request): Promise<NextResponse> {

  try {
    const cookieHeader = request.headers.get('cookie') || '';
    const token = cookieHeader.match(/(?:^|; )token=([^;]+)/)?.[1];
    const authToken = cookieHeader.match(/(?:^|; )auth-token=([^;]+)/)?.[1];
    const activeToken = authToken || token;

    if (!activeToken) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 })
    }

    const { payload } = await jwtVerify(activeToken, JWT_SECRET);
    const decoded = payload as unknown as DecodedToken;

    if (!decoded.role || !['admin'].includes(decoded.role)) {
      return NextResponse.json({ error: 'Sin permisos sofucientes' }, { status: 403 })
    }

    const body = await request.json();
    const { email, password, name, role } = body;

    if (!email || !password) {
      return NextResponse.json({ error: 'Email y contraseña son requeridos' }, { status: 400 })
    }

    // const existingUser = await checkIfUserExists(email);
    // if (existingUser) {
    //   return NextResponse.json({ error: 'El usuario ya existe' }, { status: 409 })
    // }

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = await createUsers({
      email,
      password: hashedPassword,
      name,
      role: role || 'user'
    });

    return NextResponse.json({
      message: 'Usuario creado exitosamente',
      user: newUser
    }, { status: 201 });

  } catch (error) {
    console.error('Error en /api/admin/users:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}