import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { prisma } from '@/lib/prisma';

interface DecodedToken {
  role?: string;
  userId?: string;
  id?: string;
}

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || '');


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

    // Only allow users to update their own tasks
    if (decoded.role !== 'user' && decoded.role !== 'admin') {
      return NextResponse.json({ error: 'No tienes permisos para actualizar tareas' }, { status: 403 });
    }

    const { id: taskId } = await params;
    const body = await request.json();
    const { status } = body;

    // Only allow status updates to 'terminada' (completed)
    if (status !== 'terminada') {
      return NextResponse.json({ error: 'Solo puedes marcar tareas como completadas' }, { status: 400 });
    }

    // Check if task exists and belongs to the user
    const existingTask = await prisma.task.findUnique({
      where: { id: taskId },
      include: { user: true }
    });

    if (!existingTask) {
      return NextResponse.json({ error: 'Tarea no encontrada' }, { status: 404 });
    }

    // If user is not admin, ensure they can only update their own tasks
    if (decoded.role !== 'admin' && existingTask.userId !== decoded.id) {
      return NextResponse.json({ error: 'No puedes actualizar tareas que no te pertenecen' }, { status: 403 });
    }

    // Update only the status field
    const updatedTask = await prisma.task.update({
      where: { id: taskId },
      data: { status: 'terminada' },
      include: { company: true, area: true, user: true }
    });

    return NextResponse.json({
      success: true,
      message: 'Tarea marcada como completada',
      task: updatedTask
    });

  } catch (error) {
    console.error('Error en PUT /api/tasks/[id]/status:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}
