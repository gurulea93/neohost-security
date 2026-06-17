import { useState } from "react";
import { Eye, EyeOff } from "lucide-react";
import { cn } from "@/lib/utils";

export function PasswordInput({
  className,
  value,
  onChange,
  placeholder,
  autoFocus,
  disabled,
  id,
  autoComplete = "current-password",
}) {
  const [show, setShow] = useState(false);

  return (
    <div className={cn("relative", className)}>
      <input
        id={id}
        className="form-input w-full pr-10"
        type={show ? "text" : "password"}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        autoFocus={autoFocus}
        disabled={disabled}
        autoComplete={autoComplete}
      />
      <button
        type="button"
        className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded-md text-muted-foreground hover:text-foreground transition-colors"
        onClick={() => setShow((v) => !v)}
        tabIndex={-1}
        aria-label={show ? "Ascunde parola" : "Arată parola"}
      >
        {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
      </button>
    </div>
  );
}
