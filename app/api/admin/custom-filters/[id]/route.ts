import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { jwtVerify } from 'jose';

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
    // Get the ID from params
    const { id: filterId } = await params;
    
    // Check authentication
    const cookieHeader = request.headers.get('cookie') || '';
        const token = cookieHeader.match(/(?:^|; )token=([^;]+)/)?.[1];
        const authToken = cookieHeader.match(/(?:^|; )auth-token=([^;]+)/)?.[1];
        const activeToken = authToken || token;

    if (!activeToken) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    // Verify token and check permissions
    const { payload } = await jwtVerify(activeToken, JWT_SECRET);
        const decoded = payload as unknown as DecodedToken;

    if (!decoded.role || !['admin', 'superadmin'].includes(decoded.role)) {
      return NextResponse.json({ error: 'Sin permisos suficientes' }, { status: 403 });
    }

    // Validate ID
    if (!filterId) {
      return NextResponse.json({ error: 'ID de filtro requerido' }, { status: 400 });
    }

    // Check if filter exists
    const existingFilter = await prisma.customFilter.findUnique({
      where: { id: filterId },
    });

    if (!existingFilter) {
      return NextResponse.json({ error: 'Filtro no encontrado' }, { status: 404 });
    }

    // Delete the filter
    await prisma.customFilter.delete({
      where: { id: filterId },
    });

    console.log(`✅ Filtro ${filterId} eliminado por admin ${decoded.userId || decoded.id}`);

    return NextResponse.json({
      success: true,
      message: 'Filtro eliminado exitosamente',
      deletedFilterId: filterId
    });

  } catch (error) {
    console.error('❌ Error en DELETE /api/admin/custom-filters/[id]:', error);

    // Handle JWT errors
    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    // Handle Prisma errors
    if (error instanceof Error) {
      if (error.message.includes('Foreign key constraint')) {
        return NextResponse.json({
          error: 'No se puede eliminar el filtro porque tiene datos asociados'
        }, { status: 409 });
      }

      if (error.message.includes('Record to delete does not exist')) {
        return NextResponse.json({
          error: 'El filtro ya fue eliminado'
        }, { status: 404 });
      }
    }

    return NextResponse.json({ 
      error: 'Error interno del servidor',
      details: error instanceof Error ? error.message : 'Error desconocido'
    }, { status: 500 });
  }
}
