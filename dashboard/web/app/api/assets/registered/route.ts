import { NextResponse } from 'next/server';
import fs from 'fs/promises';

const INVENTORY_FILE = process.env.SIS_DASHBOARD_INVENTORY_PATH || '/app/ot_inventory.json';

export async function GET() {
    try {
        const fileData = await fs.readFile(INVENTORY_FILE, 'utf-8');
        const inventory = JSON.parse(fileData);
        return NextResponse.json(inventory);
    } catch {
        // Si el archivo está vacío o no se ha creado, devolvemos un array vacío
        return NextResponse.json([]);
    }
}

export async function DELETE(request: Request) {
    try {
        const { ips } = await request.json() as { ips: string[] };
        if (!Array.isArray(ips) || ips.length === 0) {
            return NextResponse.json({ error: 'Selecciona al menos un activo' }, { status: 400 });
        }
        const inventory = JSON.parse(await fs.readFile(INVENTORY_FILE, 'utf-8'));
        const selected = new Set(ips.map(String));
        const remaining = inventory.filter((asset: { ip?: string }) => !selected.has(String(asset.ip || '')));
        await fs.writeFile(INVENTORY_FILE, JSON.stringify(remaining, null, 2));
        return NextResponse.json({ success: true, deleted: inventory.length - remaining.length });
    } catch (error) {
        return NextResponse.json({ error: error instanceof Error ? error.message : 'No se pudieron eliminar los activos' }, { status: 500 });
    }
}
