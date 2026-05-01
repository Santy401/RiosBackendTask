import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { prisma } from '@/lib/prisma';

interface DecodedToken {
  role?: string;
  userId?: string;
  id?: string;
}

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || '');

interface CompanyUpdateData {
  name?: string;
  tipo?: string;
  nit?: string;
  cedula?: string;
  dian?: string;
  firma?: string;
  softwareContable?: string;
  usuario?: string;
  contraseña?: string;
  servidorCorreo?: string;
  email?: string;
  claveCorreo?: string;
  claveCC?: string;
  claveSS?: string;
  claveICA?: string;
  phone?: string;
  address?: string;
  state?: boolean;
  updatedAt: Date;
}


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

    const { id: companyId } = await params;

    if (!companyId) {
      return NextResponse.json({ error: 'ID de empresa requerido' }, { status: 400 });
    }

    const existingCompany = await prisma.company.findUnique({
      where: { id: companyId },
    });

    if (!existingCompany) {
      return NextResponse.json({ error: 'Empresa no encontrada' }, { status: 404 });
    }

    if (existingCompany.tipo === 'Sistema' || existingCompany.name === 'Empresa Principal') {
      return NextResponse.json({
        error: 'No se puede eliminar la empresa principal del sistema'
      }, { status: 403 });
    }

    await prisma.company.delete({
      where: { id: companyId },
    });

    console.log(`✅ Empresa ${companyId} eliminada por admin ${decoded.userId || decoded.id}`);

    return NextResponse.json({
      success: true,
      message: 'Empresa eliminada exitosamente',
      deletedCompanyId: companyId
    });

  } catch (error: unknown) {
    console.error('❌ Error en DELETE /api/admin/companies/[id]:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    if (error instanceof Error) {
      if (error.message.includes('Foreign key constraint')) {
        return NextResponse.json({
          error: 'No se puede eliminar la empresa porque tiene usuarios o datos asociados'
        }, { status: 409 });
      }

      if (error.message.includes('Record to delete does not exist')) {
        return NextResponse.json({
          error: 'La empresa ya fue eliminada'
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

    if (!decoded.role || !['admin', 'superadmin'].includes(decoded.role)) {
      return NextResponse.json({ error: 'Sin permisos suficientes' }, { status: 403 });
    }

    const { id: companyId } = await params;

    if (!companyId) {
      return NextResponse.json({ error: 'ID de empresa requerido' }, { status: 400 });
    }

    const body = await request.json();
    const {
      name, tipo, nit, cedula, dian, firma, softwareContable,
      usuario, contraseña, servidorCorreo, email, claveCorreo,
      claveCC, claveSS, claveICA, phone, address, state
    } = body;

    const hasUpdates = [
      name, tipo, nit, cedula, dian, firma, softwareContable,
      usuario, contraseña, servidorCorreo, email, claveCorreo,
      claveCC, claveSS, claveICA, phone, address, state
    ].some(field => field !== undefined);

    if (!hasUpdates) {
      return NextResponse.json({
        error: 'Al menos un campo debe ser actualizado'
      }, { status: 400 });
    }

    if (!name && !email && !phone && !address && !nit && state === undefined) {
      return NextResponse.json({
        error: 'Al menos un campo debe ser actualizado'
      }, { status: 400 });
    }

    const existingCompany = await prisma.company.findUnique({
      where: { id: companyId },
    });

    if (!existingCompany) {
      return NextResponse.json({ error: 'Empresa no encontrada' }, { status: 404 });
    }

    if (existingCompany.tipo === 'Sistema' || existingCompany.name === 'Empresa Principal') {
      return NextResponse.json({
        error: 'No se puede modificar la empresa principal del sistema'
      }, { status: 403 });
    }

    const updateData: CompanyUpdateData = {
      updatedAt: new Date()
    };

    if (name !== undefined) updateData.name = name;
    if (tipo !== undefined) updateData.tipo = tipo;
    if (nit !== undefined) updateData.nit = nit;
    if (cedula !== undefined) updateData.cedula = cedula;
    if (dian !== undefined) updateData.dian = dian;
    if (firma !== undefined) updateData.firma = firma;
    if (softwareContable !== undefined) updateData.softwareContable = softwareContable;
    if (usuario !== undefined) updateData.usuario = usuario;
    if (contraseña !== undefined) updateData.contraseña = contraseña;
    if (servidorCorreo !== undefined) updateData.servidorCorreo = servidorCorreo;
    if (email !== undefined) updateData.email = email;
    if (claveCorreo !== undefined) updateData.claveCorreo = claveCorreo;
    if (claveCC !== undefined) updateData.claveCC = claveCC;
    if (claveSS !== undefined) updateData.claveSS = claveSS;
    if (claveICA !== undefined) updateData.claveICA = claveICA;
    if (phone !== undefined) updateData.phone = phone;
    if (address !== undefined) updateData.address = address;
    if (state !== undefined) updateData.state = state;

    // DEBUG: Ver qué se va a actualizar
    console.log('🔄 Campos a actualizar:', Object.keys(updateData));
    console.log('📝 Valor de firma:', updateData.firma);
    const updatedCompany = await prisma.company.update({
      where: { id: companyId },
      data: updateData,
    });

    console.log(`✅ Empresa ${companyId} actualizada por admin ${decoded.userId || decoded.id}`);

    return NextResponse.json({
      success: true,
      message: 'Empresa actualizada exitosamente',
      company: updatedCompany
    });

  } catch (error: unknown) {
    console.error('❌ Error en PUT /api/admin/companies/[id]:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    if (error instanceof Error) {
      if (error.message.includes('Unique constraint failed')) {
        return NextResponse.json({
          error: 'Ya existe una empresa con ese NIT o email'
        }, { status: 409 });
      }

      if (error.message.includes('Record to update not found')) {
        return NextResponse.json({
          error: 'La empresa no existe o ya fue eliminada'
        }, { status: 404 });
      }
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}