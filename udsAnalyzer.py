#!/usr/bin/env python3
"""Simple UDS analyzer GUI.

Paste raw UDS payloads (hex bytes) into the input area and decode them.
"""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import ttk

HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")

SERVICE_NAMES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x24: "ReadScalingDataByIdentifier",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x2A: "ReadDataByPeriodicIdentifier",
    0x2C: "DynamicallyDefineDataIdentifier",
    0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x83: "AccessTimingParameter",
    0x84: "SecuredDataTransmission",
    0x85: "ControlDTCSetting",
    0x86: "ResponseOnEvent",
    0x87: "LinkControl",
}

SESSION_TYPES = {
    0x01: "defaultSession",
    0x02: "programmingSession",
    0x03: "extendedDiagnosticSession",
    0x04: "safetySystemDiagnosticSession",
}

RESET_TYPES = {
    0x01: "hardReset",
    0x02: "keyOffOnReset",
    0x03: "softReset",
    0x04: "enableRapidPowerShutDown",
    0x05: "disableRapidPowerShutDown",
}

ROUTINE_TYPES = {
    0x01: "startRoutine",
    0x02: "stopRoutine",
    0x03: "requestRoutineResults",
}

NRC = {
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
}


def service_name(sid: int) -> str:
    return SERVICE_NAMES.get(sid, f"UnknownService(0x{sid:02X})")


def decode_payload(payload: list[int]) -> str:
    if not payload:
        return "Leere Payload"

    sid = payload[0]
    parts: list[str] = [f"Raw: {' '.join(f'{b:02X}' for b in payload)}"]

    if sid == 0x7F:
        if len(payload) < 3:
            parts.append("Typ: Negative Response (unvollständig)")
            return " | ".join(parts)
        req_sid = payload[1]
        nrc = payload[2]
        parts.append(
            f"Typ: Negative Response auf {service_name(req_sid)} (0x{req_sid:02X})"
        )
        parts.append(f"NRC: {NRC.get(nrc, 'UnknownNRC')} (0x{nrc:02X})")
        if len(payload) > 3:
            parts.append(f"Daten: {' '.join(f'{b:02X}' for b in payload[3:])}")
        return " | ".join(parts)

    if sid >= 0x40:
        req_sid = sid - 0x40
        parts.append(f"Typ: Positive Response auf {service_name(req_sid)} (0x{req_sid:02X})")

        if req_sid == 0x10 and len(payload) >= 2:
            sub = payload[1]
            parts.append(f"Session: {SESSION_TYPES.get(sub, 'unknown')} (0x{sub:02X})")
        elif req_sid == 0x11 and len(payload) >= 2:
            sub = payload[1]
            parts.append(f"ResetType: {RESET_TYPES.get(sub, 'unknown')} (0x{sub:02X})")
        elif req_sid == 0x22 and len(payload) >= 3:
            dids = [f"0x{payload[i]:02X}{payload[i+1]:02X}" for i in range(1, len(payload) - 1, 2)]
            parts.append(f"DID(s): {', '.join(dids)}")
        elif req_sid == 0x31 and len(payload) >= 4:
            rtype = payload[1]
            rid = (payload[2] << 8) | payload[3]
            parts.append(f"RoutineType: {ROUTINE_TYPES.get(rtype, 'unknown')} (0x{rtype:02X})")
            parts.append(f"RoutineIdentifier: 0x{rid:04X}")

        if len(payload) > 1:
            parts.append(f"Daten: {' '.join(f'{b:02X}' for b in payload[1:])}")
        return " | ".join(parts)

    parts.append(f"Typ: Request {service_name(sid)} (0x{sid:02X})")

    if sid == 0x10 and len(payload) >= 2:
        sub = payload[1]
        parts.append(f"Session: {SESSION_TYPES.get(sub, 'unknown')} (0x{sub:02X})")
    elif sid == 0x11 and len(payload) >= 2:
        sub = payload[1]
        parts.append(f"ResetType: {RESET_TYPES.get(sub, 'unknown')} (0x{sub:02X})")
    elif sid in (0x22, 0x2E) and len(payload) >= 3:
        did = (payload[1] << 8) | payload[2]
        parts.append(f"DID: 0x{did:04X}")
        if len(payload) > 3:
            parts.append(f"Daten: {' '.join(f'{b:02X}' for b in payload[3:])}")
    elif sid == 0x27 and len(payload) >= 2:
        level = payload[1]
        access = "RequestSeed" if level % 2 == 1 else "SendKey"
        parts.append(f"SecurityLevel: 0x{level:02X} ({access})")
    elif sid == 0x31 and len(payload) >= 4:
        rtype = payload[1]
        rid = (payload[2] << 8) | payload[3]
        parts.append(f"RoutineType: {ROUTINE_TYPES.get(rtype, 'unknown')} (0x{rtype:02X})")
        parts.append(f"RoutineIdentifier: 0x{rid:04X}")
        if len(payload) > 4:
            parts.append(f"RoutineData: {' '.join(f'{b:02X}' for b in payload[4:])}")
    elif len(payload) > 1:
        parts.append(f"Daten: {' '.join(f'{b:02X}' for b in payload[1:])}")

    return " | ".join(parts)


def decode_text(raw_text: str) -> str:
    decoded_lines: list[str] = []
    for idx, line in enumerate(raw_text.splitlines(), start=1):
        tokens = HEX_RE.findall(line)
        if not tokens:
            continue
        payload = [int(t, 16) for t in tokens]
        decoded_lines.append(f"Zeile {idx}: {decode_payload(payload)}")

    if not decoded_lines:
        return "Keine gültigen UDS-Bytes erkannt. Bitte Hex-Bytes wie z.B. '10 03' einfügen."
    return "\n".join(decoded_lines)


class UDSAnalyzerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("UDS Analyzer")
        self.geometry("1000x700")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(3, weight=1)

        title = ttk.Label(self, text="UDS Kommunikation Decoder", font=("Arial", 14, "bold"))
        title.grid(row=0, column=0, padx=10, pady=(10, 6), sticky="w")

        self.input_text = tk.Text(self, wrap="word", height=14)
        self.input_text.grid(row=1, column=0, padx=10, pady=6, sticky="nsew")

        button_bar = ttk.Frame(self)
        button_bar.grid(row=2, column=0, padx=10, pady=6, sticky="ew")
        button_bar.columnconfigure((0, 1, 2), weight=1)

        decode_btn = ttk.Button(button_bar, text="Dekodieren", command=self.on_decode)
        decode_btn.grid(row=0, column=0, padx=4, sticky="ew")

        clear_btn = ttk.Button(button_bar, text="Leeren", command=self.on_clear)
        clear_btn.grid(row=0, column=1, padx=4, sticky="ew")

        example_btn = ttk.Button(button_bar, text="Beispiel laden", command=self.load_example)
        example_btn.grid(row=0, column=2, padx=4, sticky="ew")

        self.output_text = tk.Text(self, wrap="word", height=14, state="disabled")
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
