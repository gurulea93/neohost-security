import { useState, useRef, useEffect } from "react";
import { ChevronDown, Check } from "lucide-react";
import { cn } from "@/lib/utils";

export function FormSelect({
  value,
  onChange,
  options = [],
  className,
  placeholder = "Selectează…",
  disabled = false,
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  useEffect(() => {
    if (!open) return;
    const onKey = (e) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  const selected = options.find((o) => String(o.value) === String(value));

  return (
    <div ref={ref} className={cn("relative", className)}>
      <button
        type="button"
        disabled={disabled}
        className={cn(
          "form-input w-full flex items-center justify-between gap-2 text-left",
          !disabled && "cursor-pointer hover:border-purple-500/40",
          open && "border-purple-500/50 ring-1 ring-purple-500/20",
          disabled && "opacity-50 cursor-not-allowed"
        )}
        onClick={() => !disabled && setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span className="truncate">{selected?.label ?? placeholder}</span>
        <ChevronDown
          className={cn(
            "w-4 h-4 shrink-0 text-muted-foreground transition-transform duration-200",
            open && "rotate-180 text-purple-400"
          )}
        />
      </button>
      {open && (
        <ul
          className="absolute z-[100] mt-1.5 w-full min-w-[10rem] rounded-xl border border-border/50 bg-card shadow-2xl py-1 max-h-56 overflow-y-auto"
          role="listbox"
        >
          {options.map((opt) => {
            const active = String(opt.value) === String(value);
            return (
              <li key={String(opt.value)}>
                <button
                  type="button"
                  role="option"
                  aria-selected={active}
                  className={cn(
                    "w-full px-3 py-2.5 text-sm text-left flex items-center justify-between gap-2 transition-colors",
                    active
                      ? "bg-purple-500/15 text-purple-300 font-medium"
                      : "text-foreground hover:bg-muted/60"
                  )}
                  onClick={() => {
                    onChange(opt.value);
                    setOpen(false);
                  }}
                >
                  <span className="truncate">{opt.label}</span>
                  {active && <Check className="w-3.5 h-3.5 shrink-0 text-purple-400" />}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
