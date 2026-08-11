import React from "react";
import { cn } from "../../utils/cn.js";

export interface ButtonGroupProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export const ButtonGroup: React.FC<ButtonGroupProps> = ({ children, className, ...props }) => {
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-[6px] border border-[#292d30] p-0.5 bg-[#000000]",
        className
      )}
      {...props}
    >
      {React.Children.map(children, (child) => {
        if (React.isValidElement(child)) {
          const childProps = child.props as { className?: string };
          return React.cloneElement(child, {
            className: cn(
              "rounded-[4px] border-none text-xs h-7 px-2.5 hover:bg-white/[0.06]",
              childProps?.className
            ),
          } as any);
        }
        return child;
      })}
    </div>
  );
};
