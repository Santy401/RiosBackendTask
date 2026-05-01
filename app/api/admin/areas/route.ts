import { NextRequest, NextResponse } from "next/server";
import { jwtVerify } from 'jose'
import { getAllArea } from "@/lib/area";
import { prisma } from "@/lib/prisma";

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

    const companies = await getAllArea();

    return NextResponse.json(companies);

  } catch (error) {
    console.error('Error en /api/admin/areas:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}

export async function POST(request: NextRequest): Promise<NextResponse> {
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

    const body = await request.json();
    const { name, state } = body;

    if (!name || name.trim() === '') {
      return NextResponse.json({ error: 'El nombre del área es requerido' }, { status: 400 });
    }

    const existingArea = await prisma.area.findFirst({
      where: {
        name: {
          equals: name.trim(),
          mode: 'insensitive'
        }
      }
    });

    if (existingArea) {
      return NextResponse.json({
        error: 'Ya existe un área con ese nombre'
      }, { status: 409 });
    }

    const newArea = await prisma.area.create({
      data: {
        name: name.trim(),
        state: state === 'activo' || state === 'true' ? 'activo' : 'inactivo',
        createdAt: new Date(),
        updatedAt: new Date()
      }
    });

    console.log(`✅ Área creada por admin ${decoded.userId || decoded.id}`);

    return NextResponse.json({
      success: true,
      message: 'Área creada exitosamente',
      area: newArea
    }, { status: 201 });

  } catch (error) {
    console.error('❌ Error en POST /api/admin/areas:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    if (error instanceof Error) {
      if (error.message.includes('Unique constraint failed')) {
        return NextResponse.json({
          error: 'Ya existe un área con ese nombre'
        }, { status: 409 });
      }
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}