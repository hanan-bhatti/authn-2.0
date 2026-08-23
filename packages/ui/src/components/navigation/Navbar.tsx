import React from "react";
import { cn } from "../../utils/cn.js";

export interface NavbarProps {
  logo?: React.ReactNode;
  brandName?: string;
  tenantSelector?: React.ReactNode;
  userMenu?: React.ReactNode;
  statusBadge?: React.ReactNode;
  className?: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  logo,
  brandName = "Authn",
  tenantSelector,
  userMenu,
  statusBadge,
  className,
}) => {
  return (
    <header
      className={cn(
        "flex items-center justify-between h-14 px-6 bg-canvas border-b border-hairline-strong w-full z-40 select-none",
        className
      )}
    >
      <div className="flex items-center gap-6">
        <a href="#" className="flex items-center gap-2 text-ink font-semibold text-sm">
          {logo || (
            <div className="w-6 h-6 rounded-md bg-canvas border border-hairline-strong flex items-center justify-center font-bold text-xs">
              A
            </div>
          )}
          <span>{brandName}</span>
        </a>

        {tenantSelector && <div className="h-4 w-px bg-hairline-strong" />}
        {tenantSelector}
      </div>

      <div className="flex items-center gap-4">
        {statusBadge}
        {userMenu}
      </div>
    </header>
  );
};
