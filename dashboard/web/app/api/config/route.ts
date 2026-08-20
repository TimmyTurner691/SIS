import { NextResponse } from 'next/server';
import Redis from 'ioredis';

const REDIS_HOST = process.env.SIS_DASHBOARD_REDIS_HOST || "redis";
const REDIS_PORT = parseInt(process.env.SIS_DASHBOARD_REDIS_PORT || "6379", 10);

const getRedisClient = () => {
    return new Redis({
        host: REDIS_HOST,
        port: REDIS_PORT,
    });
};

export async function GET() {
    try {
        const redis = getRedisClient();
        const email = await redis.get('sis_alert_email');
        redis.quit();

        return NextResponse.json({
            success: true,
            email: email || 'analista@soc-it.local'
        });
    } catch (error) {
        return NextResponse.json({ success: false, error: 'Error leyendo Redis' }, { status: 500 });
    }
}

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const { email } = body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email || !emailRegex.test(email)) {
            return NextResponse.json({ success: false, error: 'Formato de correo inválido' }, { status: 400 });
        }

        const redis = getRedisClient();
        // 1. Guardamos el correo
        await redis.set('sis_alert_email', email);

        // 2. NUEVO: Le damos la orden a Python de enviar el correo de confirmación
        await redis.set('cmd_send_test_email', 'true');

        redis.quit();

        return NextResponse.json({ success: true, message: 'Correo enlazado. Enviando prueba...' });
    } catch (error) {
        return NextResponse.json({ success: false, error: 'Error guardando en Redis' }, { status: 500 });
    }
}