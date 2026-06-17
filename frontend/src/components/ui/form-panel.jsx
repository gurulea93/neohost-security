import { cn } from "@/lib/utils";

/** Container centrat, lățime completă până la max ~1152px */
export function FormPanel({ children, className }) {
  return <div className={cn("form-panel", className)}>{children}</div>;
}

/** Grid responsive — opțional 2 coloane pe desktop */
export function FormPanelGrid({ children, className, split = false }) {
  return (
    <div className={cn("form-panel-grid", split && "form-panel-grid--split", className)}>
      {children}
    </div>
  );
}

/** Secțiune îngustă centrată (formulare simple, 2FA etc.) */
export function FormStack({ children, className }) {
  return <div className={cn("form-stack", className)}>{children}</div>;
}

/** Panou nested în card (sub-secțiuni setări) */
export function FormInset({ children, className }) {
  return <div className={cn("form-inset", className)}>{children}</div>;
}

export function FormSpanFull({ children, className }) {
  return <div className={cn("form-panel-span-full", className)}>{children}</div>;
}
