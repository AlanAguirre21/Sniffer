from scapy.all import get_if_list, get_if_hwaddr
import sys
import logging
import ctypes
import time

from interface import Interface
from capture import Capture
from analisis import Analisis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

'''
if not is_admin():
    logger.error("Este programa requiere permisos de administrador")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()
'''

def promisc_mode(interfaz):
    print("Promiscuo")


# ─────────────────────────────────────────────────────────────────────────────
def select_interface(interfaces):
    interfaz_elegida = (
        input("Ingrese el tipo de interfaz que desea utilizar \n"
              "para la captura (Wi-Fi, Ethernet, Loopback): ")
        .strip().lower().replace("-", "")
    )

    if interfaz_elegida not in ["wifi", "ethernet", "loopback"]:
        print("\n[!] Tipo de interfaz no válido. Por favor, elija entre Wi-Fi, Ethernet o Loopback.")
        time.sleep(3)
        return select_interface(interfaces)

    selected = interfaces.get(interfaz_elegida, [None])[0]

    if not selected:
        print(f"\n[!] No se encontró ninguna interfaz '{interfaz_elegida}' activa.")
        time.sleep(3)
        return select_interface(interfaces)

    tipo_display = {"wifi": "Wi-Fi", "ethernet": "Ethernet", "loopback": "Loopback"}
    print(f"[*] Interfaz {tipo_display[interfaz_elegida]} seleccionada para la captura.")
    time.sleep(2)
    return selected


# ─────────────────────────────────────────────────────────────────────────────
def select_mode():
    print("\n" + "=" * 50)
    print("  MODO DE CAPTURA")
    print("=" * 50)
    print("  1. Captura estática  (1 paquete)")
    print("  2. Captura dinámica  (flujo continuo)")
    print("=" * 50)

    modo = input("\nSeleccione el modo (1 o 2): ").strip()

    if modo not in ["1", "2"]:
        print("\n[!] Opción no válida. Ingrese 1 o 2.")
        time.sleep(2)
        return select_mode()

    return modo


# ─────────────────────────────────────────────────────────────────────────────
def select_packet(paquetes):
    Analisis.mostrar_resumen(paquetes)
    total = len(paquetes)

    while True:
        entrada = input(
            f"\nIngrese el N° de paquete a analizar [1-{total}] o 'q' para salir: "
        ).strip().lower()

        if entrada == "q":
            print("\n[*] Saliendo del análisis. ¡Hasta luego!")
            break

        try:
            idx = int(entrada)
            if 1 <= idx <= total:
                Analisis.analice_packet(paquetes[idx - 1])
                otra = input("¿Desea analizar otro paquete? (s/n): ").strip().lower()
                if otra != "s":
                    print("\n[*] Saliendo del análisis. ¡Hasta luego!")
                    break
                Analisis.mostrar_resumen(paquetes)
            else:
                print(f"[!] Número fuera de rango. Elija entre 1 y {total}.")
        except ValueError:
            print("[!] Entrada inválida. Ingrese un número o 'q' para salir.")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':

    interface_obj = Interface()
    interfaces    = interface_obj.get_all_interfaces()

    print(f"\nINTERFACES DISPONIBLES:")
    print(f"  Ethernet : {interfaces['ethernet']}")
    print(f"  Wi-Fi    : {interfaces['wifi']}")
    print(f"  Loopback : {interfaces['loopback']}\n")

    selected_interface = select_interface(interfaces)

    if not selected_interface:
        print("\n[!] No se encontró ninguna interfaz activa para iniciar la captura.")
        sys.exit(1)

    modo = select_mode()

    # PARTE 1
    if modo == "1":
        paquete = Capture.iniciar_captura(selected_interface)
        if paquete:
            print("\n[*] Captura estática completada. Iniciando análisis...\n")
            time.sleep(1)
            Analisis.analice_packet(paquete)
        else:
            print("\n[!] No se obtuvo ningún paquete para analizar.")

    # PARTE 2
    elif modo == "2":
        paquetes = Capture.captura_dinamica(selected_interface)
        if paquetes:
            print("\n[*] Captura dinámica completada. Iniciando selección de paquete...\n")
            time.sleep(1)
            select_packet(paquetes)
        else:
            print("\n[!] No se capturó ningún paquete durante el flujo.")
