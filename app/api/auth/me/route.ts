import { NextResponse } from 'next/server';
import { jwtVerify } from 'jose';

interface DecodedToken {
    role?: string;
    userId?: string;
    id?: string;
    email?: string;
}

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || '');

export async function GET(request: Request): Promise<NextResponse> {
    try {
        console.log('🔐 Verificando token en /api/auth/me');

        const cookieHeader = request.headers.get('cookie') || '';
        const token = cookieHeader.match(/(?:^|; )token=([^;]+)/)?.[1];
        const authToken = cookieHeader.match(/(?:^|; )auth-token=([^;]+)/)?.[1];
        const activeToken = authToken || token;

        console.log('🍪 Token encontrado:', !!activeToken);

        if (!activeToken) {
            console.log('❌ No hay token');
            return NextResponse.json({ error: 'No autenticado' }, { status: 401 });
        }

        const { payload } = await jwtVerify(activeToken, JWT_SECRET);
        const decoded = payload as unknown as DecodedToken;
        console.log('📖 Token decodificado:', decoded);

        return NextResponse.json({
            id: decoded.id,
            email: decoded.email,
            role: decoded.role
        });

    } catch (error) {
        console.error('💥 Error en /api/auth/me:', error);
        return NextResponse.json({ error: 'Token inválido' }, { status: 401 });
    }
}