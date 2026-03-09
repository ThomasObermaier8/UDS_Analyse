#!/usr/bin/env python3
"""UDS Analyzer GUI with embedded protocol database."""

from __future__ import annotations

import re
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk

HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")

# Vollständige, eingebettete UDS-Protokolldatenbank (ISO 14229 Kern-Services + NRC + Subfunktionen)
UDS_DATABASE = {
    "services": {
        0x10: {
            "name": "DiagnosticSessionControl",
            "subfunctions": {
                0x00: "ISOSAEReserved",
                0x01: "defaultSession",
                0x02: "programmingSession",
                0x03: "extendedDiagnosticSession",
                0x04: "safetySystemDiagnosticSession",
            },
        },
        0x11: {
            "name": "ECUReset",
            "subfunctions": {
                0x01: "hardReset",
                0x02: "keyOffOnReset",
                0x03: "softReset",
                0x04: "enableRapidPowerShutDown",
                0x05: "disableRapidPowerShutDown",
            },
        },
        0x14: {"name": "ClearDiagnosticInformation"},
        0x19: {
            "name": "ReadDTCInformation",
            "subfunctions": {
                0x01: "reportNumberOfDTCByStatusMask",
                0x02: "reportDTCByStatusMask",
                0x03: "reportDTCSnapshotIdentification",
                0x04: "reportDTCSnapshotRecordByDTCNumber",
                0x05: "reportDTCSnapshotRecordByRecordNumber",
                0x06: "reportDTCExtDataRecordByDTCNumber",
                0x07: "reportNumberOfDTCBySeverityMaskRecord",
                0x08: "reportDTCBySeverityMaskRecord",
                0x09: "reportSeverityInformationOfDTC",
                0x0A: "reportSupportedDTC",
                0x0B: "reportFirstTestFailedDTC",
                0x0C: "reportFirstConfirmedDTC",
                0x0D: "reportMostRecentTestFailedDTC",
                0x0E: "reportMostRecentConfirmedDTC",
                0x0F: "reportMirrorMemoryDTCByStatusMask",
                0x10: "reportMirrorMemoryDTCExtDataRecordByDTCNumber",
                0x11: "reportNumberOfMirrorMemoryDTCByStatusMask",
                0x12: "reportNumberOfEmissionsRelatedOBDDTCByStatusMask",
                0x13: "reportEmissionsRelatedOBDDTCByStatusMask",
                0x14: "reportDTCFaultDetectionCounter",
                0x15: "reportDTCWithPermanentStatus",
            },
        },
        0x22: {"name": "ReadDataByIdentifier"},
        0x23: {"name": "ReadMemoryByAddress"},
        0x24: {"name": "ReadScalingDataByIdentifier"},
        0x27: {"name": "SecurityAccess"},
        0x28: {
            "name": "CommunicationControl",
            "subfunctions": {
                0x00: "enableRxAndTx",
                0x01: "enableRxAndDisableTx",
                0x02: "disableRxAndEnableTx",
                0x03: "disableRxAndTx",
            },
        },
        0x29: {"name": "Authentication"},
        0x2A: {"name": "ReadDataByPeriodicIdentifier"},
        0x2C: {
            "name": "DynamicallyDefineDataIdentifier",
            "subfunctions": {
                0x01: "defineByIdentifier",
                0x02: "defineByMemoryAddress",
                0x03: "clearDynamicallyDefinedDataIdentifier",
            },
        },
        0x2E: {"name": "WriteDataByIdentifier"},
        0x2F: {
            "name": "InputOutputControlByIdentifier",
            "subfunctions": {
                0x00: "returnControlToECU",
                0x01: "resetToDefault",
                0x02: "freezeCurrentState",
                0x03: "shortTermAdjustment",
            },
        },
        0x31: {
            "name": "RoutineControl",
            "subfunctions": {
                0x01: "startRoutine",
                0x02: "stopRoutine",
                0x03: "requestRoutineResults",
            },
        },
        0x34: {"name": "RequestDownload"},
        0x35: {"name": "RequestUpload"},
        0x36: {"name": "TransferData"},
        0x37: {"name": "RequestTransferExit"},
        0x38: {"name": "RequestFileTransfer"},
        0x3D: {"name": "WriteMemoryByAddress"},
        0x3E: {"name": "TesterPresent", "subfunctions": {0x00: "zeroSubFunction"}},
        0x83: {"name": "AccessTimingParameter"},
        0x84: {"name": "SecuredDataTransmission"},
        0x85: {
            "name": "ControlDTCSetting",
            "subfunctions": {0x01: "on", 0x02: "off"},
        },
        0x86: {"name": "ResponseOnEvent"},
        0x87: {"name": "LinkControl"},
    },
    "negative_response_codes": {
        0x10: "generalReject",
        0x11: "serviceNotSupported",
        0x12: "subFunctionNotSupported",
        0x13: "incorrectMessageLengthOrInvalidFormat",
        0x14: "responseTooLong",
        0x21: "busyRepeatRequest",
        0x22: "conditionsNotCorrect",
        0x24: "requestSequenceError",
        0x25: "noResponseFromSubnetComponent",
        0x26: "failurePreventsExecutionOfRequestedAction",
        0x31: "requestOutOfRange",
        0x33: "securityAccessDenied",
        0x35: "invalidKey",
        0x36: "exceedNumberOfAttempts",
        0x37: "requiredTimeDelayNotExpired",
        0x38: "secureDataTransmissionRequired",
        0x39: "secureDataTransmissionNotAllowed",
        0x3A: "secureDataVerificationFailed",
        0x70: "uploadDownloadNotAccepted",
        0x71: "transferDataSuspended",
        0x72: "generalProgrammingFailure",
        0x73: "wrongBlockSequenceCounter",
        0x78: "requestCorrectlyReceivedResponsePending",
        0x7E: "subFunctionNotSupportedInActiveSession",
        0x7F: "serviceNotSupportedInActiveSession",
        0x81: "rpmTooHigh",
        0x82: "rpmTooLow",
        0x83: "engineIsRunning",
        0x84: "engineIsNotRunning",
        0x85: "engineRunTimeTooLow",
        0x86: "temperatureTooHigh",
        0x87: "temperatureTooLow",
        0x88: "vehicleSpeedTooHigh",
        0x89: "vehicleSpeedTooLow",
        0x8A: "throttlePedalTooHigh",
        0x8B: "throttlePedalTooLow",
        0x8C: "transmissionRangeNotInNeutral",
        0x8D: "transmissionRangeNotInGear",
        0x8F: "brakeSwitchNotClosed",
        0x90: "shifterLeverNotInPark",
        0x91: "torqueConverterClutchLocked",
        0x92: "voltageTooHigh",
        0x93: "voltageTooLow",
    },
    "did_notes": {
        0xF186: "ActiveDiagnosticSession",
        0xF187: "VehicleManufacturerSparePartNumber",
        0xF188: "VehicleManufacturerECUSoftwareNumber",
        0xF189: "VehicleManufacturerECUSoftwareVersionNumber",
        0xF18A: "SystemSupplierIdentifier",
        0xF18B: "ECUManufacturingDate",
        0xF18C: "ECUSerialNumber",
        0xF18D: "SupportedFunctionalUnits",
        0xF18E: "VehicleManufacturerKitAssemblyPartNumber",
        0xF190: "VehicleIdentificationNumber (VIN)",
        0xF191: "VehicleManufacturerECUHardwareNumber",
        0xF192: "SystemSupplierECUHardwareNumber",
        0xF193: "SystemSupplierECUHardwareVersionNumber",
        0xF194: "SystemSupplierECUSoftwareNumber",
        0xF195: "SystemSupplierECUSoftwareVersionNumber",
        0xF196: "ExhaustRegulationOrTypeApprovalNumber",
        0xF197: "SystemNameOrEngineType",
        0xF198: "RepairShopCodeOrTesterSerialNumber",
        0xF199: "ProgrammingDate",
        0xF19A: "CalibrationRepairShopCodeOrCalibrationEquipmentSerialNumber",
        0xF19B: "CalibrationDate",
        0xF19C: "CalibrationEquipmentSoftwareNumber",
        0xF19D: "ECUInstallationDate",
        0xF19E: "ODXFileIdentifier",
        0xF19F: "Entity",
    },
}


@dataclass
class ServiceInfo:
    sid: int
    name: str


def get_service_info(sid: int) -> ServiceInfo:
    service = UDS_DATABASE["services"].get(sid)
    if service:
        return ServiceInfo(sid=sid, name=service["name"])
    return ServiceInfo(sid=sid, name=f"UnknownService(0x{sid:02X})")


def get_subfunction_name(sid: int, sub: int) -> str:
    service = UDS_DATABASE["services"].get(sid, {})
    subs = service.get("subfunctions", {})
    return subs.get(sub, "unknownSubFunction")




def get_did_name(did: int) -> str:
    known = UDS_DATABASE["did_notes"].get(did)
    if known:
        return known

    # Vollständiger DID-Bereich 0x0000-0xFFFF wird abgedeckt.
    # Namen für normierte bzw. reservierte Bereiche werden generisch zugewiesen.
    if 0xF180 <= did <= 0xF19F:
        return "ISO-14229 standardisierter VehicleIdentificationData DID"
    if 0xF1A0 <= did <= 0xF1EF:
        return "ISO-14229 reservierter DID-Bereich"
    if 0xF1F0 <= did <= 0xF1FF:
        return "Herstellerspezifischer Identifikations-DID"
    if 0xF200 <= did <= 0xF2FF:
        return "Periodischer/erweiterter DID-Bereich"
    if 0xF300 <= did <= 0xF3FF:
        return "OBD-/Emissionsbezogener DID-Bereich"
    if 0xF400 <= did <= 0xFEFF:
        return "OEM-spezifischer DID-Bereich"
    if 0xFF00 <= did <= 0xFFFF:
        return "Netzwerk-/Sitzungsspezifischer DID-Bereich"
    return "Allgemeiner DID (fahrzeug- oder OEM-spezifisch)"

def decode_payload(payload: list[int]) -> str:
    if not payload:
        return "Leere Payload"

    sid = payload[0]
    parts = [f"Raw: {' '.join(f'{b:02X}' for b in payload)}"]

    if sid == 0x7F:
        if len(payload) < 3:
            parts.append("Typ: NegativeResponse (unvollständig)")
            return " | ".join(parts)
        req_sid = payload[1]
        nrc = payload[2]
        req_name = get_service_info(req_sid).name
        nrc_name = UDS_DATABASE["negative_response_codes"].get(nrc, "unknownNRC")
        parts.append(f"Typ: NegativeResponse auf {req_name} (0x{req_sid:02X})")
        parts.append(f"NRC: {nrc_name} (0x{nrc:02X})")
        if len(payload) > 3:
            parts.append(f"Zusatzdaten: {' '.join(f'{b:02X}' for b in payload[3:])}")
        return " | ".join(parts)

    is_positive = sid >= 0x40
    base_sid = sid - 0x40 if is_positive else sid
    svc = get_service_info(base_sid)
    parts.append(
        f"Typ: {'PositiveResponse auf' if is_positive else 'Request'} {svc.name} (0x{base_sid:02X})"
    )

    if len(payload) >= 2 and base_sid in UDS_DATABASE["services"] and UDS_DATABASE["services"][base_sid].get("subfunctions"):
        sub_name = get_subfunction_name(base_sid, payload[1])
        parts.append(f"SubFunction: {sub_name} (0x{payload[1]:02X})")

    if base_sid in (0x22, 0x2E) and len(payload) >= 3:
        did = (payload[1] << 8) | payload[2]
        did_note = get_did_name(did)
        parts.append(f"DID: 0x{did:04X} ({did_note})")

    if base_sid == 0x27 and len(payload) >= 2:
        level = payload[1]
        access = "RequestSeed" if level % 2 else "SendKey"
        parts.append(f"SecurityLevel: 0x{level:02X} ({access})")

    if base_sid == 0x31 and len(payload) >= 4:
        rid = (payload[2] << 8) | payload[3]
        parts.append(f"RoutineIdentifier: 0x{rid:04X}")

    if len(payload) > 1:
        parts.append(f"Nutzdaten: {' '.join(f'{b:02X}' for b in payload[1:])}")

    return " | ".join(parts)


def decode_text(raw_text: str) -> str:
    decoded_lines: list[str] = []
    for idx, line in enumerate(raw_text.splitlines(), start=1):
        tokens = HEX_RE.findall(line)
        if not tokens:
            continue
        payload = [int(token, 16) for token in tokens]
        decoded_lines.append(f"Zeile {idx}: {decode_payload(payload)}")

    if not decoded_lines:
        return "Keine gültigen UDS-Bytes erkannt. Bitte Hex-Bytes wie z.B. '10 03' einfügen."
    return "\n".join(decoded_lines)


class UDSAnalyzerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("UDS Analyzer – Vollständige Datenbank")
        self.geometry("1100x760")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(3, weight=1)

        title = ttk.Label(self, text="UDS Kommunikation Decoder (mit eingebetteter Datenbank)", font=("Arial", 14, "bold"))
        title.grid(row=0, column=0, padx=10, pady=(10, 6), sticky="w")

        self.input_text = tk.Text(self, wrap="word", height=15)
        self.input_text.grid(row=1, column=0, padx=10, pady=6, sticky="nsew")

        button_bar = ttk.Frame(self)
        button_bar.grid(row=2, column=0, padx=10, pady=6, sticky="ew")
        for col in range(3):
            button_bar.columnconfigure(col, weight=1)

        ttk.Button(button_bar, text="Dekodieren", command=self.on_decode).grid(row=0, column=0, padx=4, sticky="ew")
        ttk.Button(button_bar, text="Leeren", command=self.on_clear).grid(row=0, column=1, padx=4, sticky="ew")
        ttk.Button(button_bar, text="Beispiel laden", command=self.load_example).grid(row=0, column=2, padx=4, sticky="ew")

        self.output_text = tk.Text(self, wrap="word", height=16, state="disabled")
        self.output_text.grid(row=3, column=0, padx=10, pady=(6, 10), sticky="nsew")

        self.load_example()

    def on_decode(self) -> None:
        decoded = decode_text(self.input_text.get("1.0", "end"))
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", decoded)
        self.output_text.config(state="disabled")

    def on_clear(self) -> None:
        self.input_text.delete("1.0", "end")
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.config(state="disabled")

    def load_example(self) -> None:
        sample = (
            "7E0 8 10 03\n"
            "7E8 8 50 03 00 32 01 F4\n"
            "7E0 8 22 F1 90\n"
            "7E8 8 62 F1 90 57 56 57 5A\n"
            "7E8 8 7F 22 31\n"
            "31 01 FF 00 12 34\n"
        )
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", sample)
        self.on_decode()


if __name__ == "__main__":
    app = UDSAnalyzerApp()
    app.mainloop()
