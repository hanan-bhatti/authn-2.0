import React from "react";
import { Chevron } from "../display/Chevron.js";
import { Button } from "../actions/Button.js";
import { cn } from "../../utils/cn.js";

export interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  className?: string;
}

export const Pagination: React.FC<PaginationProps> = ({
  currentPage,
  totalPages,
  onPageChange,
  className,
}) => {
  return (
    <div className={cn("flex items-center justify-between px-2 py-3 border-t border-[#292d30] w-full text-xs font-mono text-[#a1a4a5] select-none", className)}>
      <span>
        Page <span className="text-white font-medium">{currentPage}</span> of{" "}
        <span className="text-white font-medium">{totalPages}</span>
      </span>

      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={currentPage <= 1}
          onClick={() => onPageChange(currentPage - 1)}
          leftIcon={<Chevron direction="left" size="sm" />}
        >
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={currentPage >= totalPages}
          onClick={() => onPageChange(currentPage + 1)}
          rightIcon={<Chevron direction="right" size="sm" />}
        >
          Next
        </Button>
      </div>
    </div>
  );
};
