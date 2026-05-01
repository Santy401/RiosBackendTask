import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { prisma } from '@/lib/prisma';
import { updateTask } from "@/lib/task";

interface UpdateTask {
  name?: string;
  description?: string;
  dueDate?: Date;
  status?: string;
  companyId?: string;
  areaId?: string;
  userId?: string;
}

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

    const { id: taskId } = await params;

    if (!taskId) {
      return NextResponse.json({ error: 'ID de Tarea requerido' }, { status: 400 });
    }

    const existingTask = await prisma.task.findUnique({
      where: { id: taskId },
    });

    if (!existingTask) {
      return NextResponse.json({ error: 'Tarea no encontrada' }, { status: 404 });
    }

    await prisma.task.delete({
      where: { id: taskId },
    });

    console.log(`✅ Tarea ${taskId} eliminada por admin ${decoded.userId || decoded.id}`);

    return NextResponse.json({
      success: true,
      message: 'Tarea eliminada exitosamente',
      deletedTaskId: taskId
    });

  } catch (error) {
    console.error('❌ Error en DELETE /api/admin/tasks/[id]:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    if (error instanceof Error) {
      if (error.message.includes('Foreign key constraint')) {
        return NextResponse.json({
          error: 'No se puede eliminar la Tarea porque tiene usuarios o datos asociados'
        }, { status: 409 });
      }

      if (error.message.includes('Record to delete does not exist')) {
        return NextResponse.json({
          error: 'La Tarea ya fue eliminada'
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

    const { id: taskId } = await params;

    if (!taskId) {
      return NextResponse.json({ error: 'ID de Tarea requerido' }, { status: 400 });
    }

    const body = await request.json();
    const { name, description, dueDate, status, companyId, areaId, userId } = body;

    if (!name && !description && !dueDate && !status && !companyId && !areaId && !userId) {
      return NextResponse.json({ error: 'Al menos un campo debe ser actualizado' }, { status: 400 });
    }

    const existingTask = await prisma.task.findUnique({
      where: { id: taskId },
    });

    if (!existingTask) {
      return NextResponse.json({ error: 'Tarea no encontrada' }, { status: 404 });
    }

    if (companyId) {
      const companyExists = await prisma.company.findUnique({
        where: { id: companyId },
      });
      if (!companyExists) {
        return NextResponse.json({ error: 'Compañía no encontrada' }, { status: 404 });
      }
    }

    if (areaId) {
      const areaExists = await prisma.area.findUnique({
        where: { id: areaId },
      });
      if (!areaExists) {
        return NextResponse.json({ error: 'Área no encontrada' }, { status: 404 });
      }
    }

    if (userId) {
      const userExists = await prisma.user.findUnique({
        where: { id: userId },
      });
      if (!userExists) {
        return NextResponse.json({ error: 'Usuario no encontrado' }, { status: 404 });
      }
    }

    const updateData: UpdateTask = {};
    if (name) updateData.name = name;
    if (description) updateData.description = description;
    if (dueDate) updateData.dueDate = new Date(dueDate);
    if (status) updateData.status = status;
    if (companyId) updateData.companyId = companyId;
    if (areaId) updateData.areaId = areaId;
    if (userId) updateData.userId = userId;

    const updatedTask = await updateTask(taskId, updateData);

    console.log(`✅ Tarea ${taskId} actualizada por admin ${decoded.userId || decoded.id}`);

    return NextResponse.json({
      success: true,
      message: 'Tarea actualizada exitosamente',
      task: updatedTask
    });

  } catch (error) {
    console.error('❌ Error en PUT /api/admin/tasks/[id]:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    if (error instanceof Error) {
      if (error.message.includes('Unique constraint failed')) {
        return NextResponse.json({
          error: 'Ya existe una tarea con ese nombre'
        }, { status: 409 });
      }

      if (error.message.includes('Foreign key constraint')) {
        return NextResponse.json({
          error: 'Error de referencia: compañía, área o usuario no válido'
        }, { status: 409 });
      }

      if (error.message.includes('Record to update not found')) {
        return NextResponse.json({
          error: 'La tarea no existe o ya fue eliminada'
        }, { status: 404 });
      }
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}