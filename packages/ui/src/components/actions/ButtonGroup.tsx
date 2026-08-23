import React from "react";
import { cn } from "../../utils/cn.js";

export interface ButtonGroupProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export const ButtonGroup: React.FC<ButtonGroupProps> = ({ children, className, ...props }) => {
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-md border border-hairline-strong p-0.5 bg-canvas",
        className
      )}
      {...props}
    >
      {React.Children.map(children, (child) => {
        if (React.isValidElement(child)) {
          const childProps = child.props as { className?: string };
          return React.cloneElement(child, {
            className: cn(
              "rounded-xs border-none text-xs h-7 px-2.5 hover:bg-ink/[0.06]",
              childProps?.className
            ),
          } as any);
        }
        return child;
      })}
    </div>
  );
};
