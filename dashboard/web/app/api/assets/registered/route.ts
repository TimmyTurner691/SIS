import { NextResponse } from 'next/server';
import fs from 'fs/promises';

export async function GET() {
    const INVENTORY_FILE = process.env.SIS_DASHBOARD_INVENTORY_PATH || '/app/ot_inventory.json';

    try {
        const fileData = await fs.readFile(INVENTORY_FILE, 'utf-8');
        const inventory = JSON.parse(fileData);
        return NextResponse.json(inventory);
    } catch (error) {
        // Si el archivo está vacío o no se ha creado, devolvemos un array vacío
        return NextResponse.json([]);
    }
}