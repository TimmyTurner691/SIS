import { NextRequest, NextResponse } from "next/server";
import Redis from "ioredis";

const REDIS_HOST = process.env.SIS_DASHBOARD_REDIS_HOST || "redis";
const REDIS_PORT = parseInt(process.env.SIS_DASHBOARD_REDIS_PORT || "6379", 10);

const redis = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const instruction = body.instruction || body.command || body;

    if (instruction === "reset_ia") {
      await redis.set("cmd_reset_brain", "true");
      await redis.del("sis_queue");
      return NextResponse.json({ success: true, message: "Operación exitosa: reset_ia", instruction });
    } 
    
    if (instruction === "reset_demo") {
      await redis.set("cmd_full_reset_demo", "true");
      await redis.del("sis_queue");
      return NextResponse.json({ success: true, message: "Operación exitosa: reset_demo", instruction });
    } 
    
    if (instruction === "force_train") {
      await redis.set("cmd_force_train", "true");
      return NextResponse.json({ success: true, message: "Operación exitosa: force_train", instruction });
    }

    return NextResponse.json({ success: false, message: "Instrucción no válida." }, { status: 400 });

  } catch (error) {
    console.error("Error en API /api/command:", error);
    return NextResponse.json({ success: false, message: "Error interno del servidor" }, { status: 500 });
  }
}
