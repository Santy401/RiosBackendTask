import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { prisma } from '@/lib/prisma';

interface DecodedToken {
  role?: string;
  userId?: string;
  id?: string;
}

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || '');

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  try {
    const { id: areaId } = await params;
    
    const cookieHeader = request.headers.get('cookie') || '';
        const token = cookieHeader.match(/(?:^|; )token=([^;]+)/)?.[1];
        const authToken = cookieHeader.match(/(?:^|; )auth-token=([^;]+)/)?.[1];
        const activeToken = authToken || token;

    if (!activeToken) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const { payload } = await jwtVerify(activeToken, JWT_SECRET);
        const decoded = payload as unknown as DecodedToken;

    if (!decoded.role || !['admin', 'superadmin'].includes(decoded.role)) {
      return NextResponse.json({ error: 'Sin permisos suficientes' }, { status: 403 });
    }

    if (!areaId) {
      return NextResponse.json({ error: 'ID de area requerido' }, { status: 400 });
    }

    const existingArea = await prisma.area.findUnique({
      where: { id: areaId },
    });

    if (!existingArea) {
      return NextResponse.json({ error: 'area no encontrada' }, { status: 404 });
    }

    await prisma.area.delete({
      where: { id: areaId },
    });

    console.log(`✅ area ${areaId} eliminada por admin ${decoded.userId || decoded.id}`);

    return NextResponse.json({
      success: true,
      message: 'Empresa eliminada exitosamente',
      deletedAreaId: areaId
    });

  } catch (error) {
    console.error('❌ Error en DELETE /api/admin/area/[id]:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    if (error instanceof Error) {
      if (error.message.includes('Foreign key constraint')) {
        return NextResponse.json({
          error: 'No se puede eliminar la area porque tiene datos asociados'
        }, { status: 409 });
      }

      if (error.message.includes('Record to delete does not exist')) {
        return NextResponse.json({
          error: 'La area ya fue eliminada'
        }, { status: 404 });
      }
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  try {
    const { id: areaId } = await params;
    
    const cookieHeader = request.headers.get('cookie') || '';
        const token = cookieHeader.match(/(?:^|; )token=([^;]+)/)?.[1];
        const authToken = cookieHeader.match(/(?:^|; )auth-token=([^;]+)/)?.[1];
        const activeToken = authToken || token;

    if (!activeToken) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const { payload } = await jwtVerify(activeToken, JWT_SECRET);
        const decoded = payload as unknown as DecodedToken;

    if (!decoded.role || !['admin', 'superadmin'].includes(decoded.role)) {
      return NextResponse.json({ error: 'Sin permisos suficientes' }, { status: 403 });
    }

    if (!areaId) {
      return NextResponse.json({ error: 'ID de área requerido' }, { status: 400 });
    }

    const body = await request.json();
    const { name, companyId, status } = body;

    if (!name || name.trim() === '') {
      return NextResponse.json({ error: 'El nombre del área es requerido' }, { status: 400 });
    }

    const existingArea = await prisma.area.findUnique({
      where: { id: areaId },
    });

    if (!existingArea) {
      return NextResponse.json({ error: 'Área no encontrada' }, { status: 404 });
    }

    if (companyId) {
      const companyExists = await prisma.company.findUnique({
        where: { id: companyId },
      });

      if (!companyExists) {
        return NextResponse.json({ error: 'Compañía no encontrada' }, { status: 404 });
      }
    }

    const updatedArea = await prisma.area.update({
      where: { id: areaId },
      data: {
        name: name.trim(),
        state: status !== undefined ? status : existingArea.state,
        updatedAt: new Date(),
      },
    });

    console.log(`✅ Área ${areaId} actualizada por admin ${decoded.userId || decoded.id}`);

    return NextResponse.json({
      success: true,
      message: 'Área actualizada exitosamente',
      area: updatedArea
    });

  } catch (error) {
    console.error('❌ Error en PUT /api/admin/area/[id]:', error);

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

      if (error.message.includes('Foreign key constraint')) {
        return NextResponse.json({
          error: 'Error de referencia: compañía no válida'
        }, { status: 409 });
      }

      if (error.message.includes('Record to update not found')) {
        return NextResponse.json({
          error: 'El área no existe o ya fue eliminada'
        }, { status: 404 });
      }
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}