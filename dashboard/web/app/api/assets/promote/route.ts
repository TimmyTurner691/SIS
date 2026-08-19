import { NextResponse } from 'next/server';
import fs from 'fs/promises';

// Usamos la misma variable de entorno que tenías en Python
const INVENTORY_FILE = process.env.SIS_DASHBOARD_INVENTORY_PATH || '/app/ot_inventory.json';

export async function POST(req: Request) {
    try {
        const { assets } = await req.json();
        if (!assets || !assets.length) {
            return NextResponse.json({ error: 'Ningún activo seleccionado' }, { status: 400 });
        }

        let inventory: any[] = [];
        try {
            const fileData = await fs.readFile(INVENTORY_FILE, 'utf-8');
            inventory = JSON.parse(fileData);
        } catch (e) {
            // Si el archivo no existe aún, empezamos con un array vacío
        }

        let promotedCount = 0;

        // Lógica de promoción
        assets.forEach((asset: any) => {
            const exists = inventory.find((item: any) => item.ip === asset.ip);
            // Validamos que tenga IP y no esté duplicado
            if (!exists && asset.ip) {
                inventory.push({
                    ip: asset.ip,
                    name: asset.hostname || `Descubierto_${asset.ip}`,
                    type: "UNKNOWN",
                    mac: asset.mac || "N/A",
                    vendor: asset.vendor_oui || "Desconocido",
                    criticidad: asset.criticidad_sugerida || "LOW"
                });
                promotedCount++;
            }
        });

        await fs.writeFile(INVENTORY_FILE, JSON.stringify(inventory, null, 2));

        return NextResponse.json({ message: `Se promovieron ${promotedCount} activos al inventario OT.` });
    } catch (error) {
        return NextResponse.json({ error: 'Error interno guardando en el inventario' }, { status: 500 });
    }
}