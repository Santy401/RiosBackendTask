import { NextResponse } from "next/server";
import { jwtVerify } from 'jose';
import { getAllCompany, createCompany } from "@/lib/company";

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

    const companies = await getAllCompany();

    return NextResponse.json(companies);

  } catch (error: unknown) {
    console.error('Error en /api/admin/companies:', error);

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
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const { payload } = await jwtVerify(activeToken, JWT_SECRET);
    const decoded = payload as unknown as DecodedToken;

    if (decoded.role !== 'admin') {
      return NextResponse.json({ error: 'No tienes permisos de administrador' }, { status: 403 });
    }

    const body = await request.json();
    const { name, tipo, nit, cedula, dian, firma, softwareContable, usuario, contraseña, servidorCorreo, email, claveCorreo, claveCC, claveSS, claveICA } = body;

    if (!name || !nit || !email) {
      return NextResponse.json({ error: 'Nombre, NIT y email son requeridos' }, { status: 400 });
    }

    // const existingCompany = await checkIfCompanyExists(nit, email);
    // if (existingCompany) {
    //   return NextResponse.json({ error: 'Ya existe una empresa con este NIT o email' }, { status: 409 });
    // }

    const newCompany = await createCompany({
      name,
      tipo,
      nit,
      cedula,
      dian,
      firma,
      softwareContable,
      usuario,
      contraseña,
      servidorCorreo,
      email,
      claveCorreo,
      claveCC,
      claveSS,
      claveICA
    });

    console.log('✅ Empresa creada exitosamente:', newCompany.id);

    return NextResponse.json({
      success: true,
      message: 'Empresa creada exitosamente',
      company: newCompany
    }, { status: 201 });

  } catch (error: unknown) {
    console.error('Error en POST /api/admin/companies:', error);

    if (error instanceof Error && error.name === 'JWTInvalid') {
      return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }

    if (error instanceof Error && error.name === 'JWTExpired') {
      return NextResponse.json({ error: 'Token expirado' }, { status: 401 });
    }

    if (error instanceof Error && error.message.includes('unique constraint')) {
      return NextResponse.json({ error: 'Ya existe una empresa con este NIT o email' }, { status: 409 });
    }

    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}