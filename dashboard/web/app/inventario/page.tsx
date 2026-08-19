import DiscoveredAssets from '../DiscoveredAssets';
import RegisteredAssets from '../RegisteredAssets';

export default function InventarioPage() {
    return (
        <div className="flex flex-col gap-8">
            <div>
                <h1 className="text-3xl font-bold text-white mb-2">Gestión de Activos OT/IT</h1>
                <p className="text-gray-400">Descubrimiento y clasificación de dispositivos en la red industrial.</p>
            </div>

            {/* Tu inventario oficial seguro */}
            <RegisteredAssets />

            {/* La zona de descubrimiento para promover nuevos equipos */}
            <DiscoveredAssets />
        </div>
    );
}