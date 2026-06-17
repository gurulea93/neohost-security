import { cn } from "@/lib/utils";
import Icon from "../../Icons";
import { useI18n } from "../../i18n";

const TAB_DEFS = [
  { id: "account", labelKey: "profile.account", icon: "users" },
  { id: "branding", labelKey: "profile.branding", icon: "activity" },
  { id: "notifications", labelKey: "profile.notifications", icon: "link" },
  { id: "sessions", labelKey: "profile.sessions", icon: "server" },
  { id: "2fa", labelKey: "profile.2fa", icon: "lock" },
  { id: "telegram", labelKey: "profile.telegram", icon: "link" },
  { id: "whitelist", labelKey: "profile.whitelist", icon: "shield" },
];

export function ProfileTabs({ active, onChange }) {
  const { t } = useI18n();
  return (
    <div className="profile-tabs" role="tablist">
      {TAB_DEFS.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={active === tab.id}
          className={cn("profile-tab", active === tab.id && "profile-tab-active")}
          onClick={() => onChange(tab.id)}
        >
          <Icon name={tab.icon} size={15} />
          <span>{t(tab.labelKey)}</span>
        </button>
      ))}
    </div>
  );
}
