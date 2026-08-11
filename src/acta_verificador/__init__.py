# Copyright 2026 Eleion — Apache-2.0
"""Verificador de actas de evidencia de Eleion Acta."""
from .cadena import (ESQUEMA, Resultado, cargar_estricto, verificar,
                     verificar_archivo, verificar_integridad, verificar_procedencia)

__version__ = "0.1.2"
__all__ = ["ESQUEMA", "Resultado", "verificar", "verificar_integridad",
           "verificar_procedencia", "verificar_archivo", "cargar_estricto",
           "__version__"]
