import React from "react";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "./Table.js";
import { Checkbox } from "../inputs/Checkbox.js";

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  cell: (row: T) => React.ReactNode;
  isMonospace?: boolean;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (row: T) => string;
  selectable?: boolean;
  selectedKeys?: string[];
  onSelectionChange?: (selectedKeys: string[]) => void;
  emptyMessage?: string;
}

export function DataTable<T>({
  columns,
  data,
  keyExtractor,
  selectable = false,
  selectedKeys = [],
  onSelectionChange,
  emptyMessage = "No records found.",
}: DataTableProps<T>) {
  const allKeys = data.map(keyExtractor);
  const isAllSelected = allKeys.length > 0 && allKeys.every((k) => selectedKeys.includes(k));

  const toggleAll = () => {
    if (isAllSelected) {
      onSelectionChange?.([]);
    } else {
      onSelectionChange?.(allKeys);
    }
  };

  const toggleRow = (key: string) => {
    if (selectedKeys.includes(key)) {
      onSelectionChange?.(selectedKeys.filter((k) => k !== key));
    } else {
      onSelectionChange?.([...selectedKeys, key]);
    }
  };

  return (
    <Table>
      <TableHeader>
        <TableRow>
          {selectable && (
            <TableHead className="w-10">
              <Checkbox checked={isAllSelected} onChange={toggleAll} />
            </TableHead>
          )}
          {columns.map((col) => (
            <TableHead key={col.key}>{col.header}</TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.length === 0 ? (
          <TableRow>
            <TableCell colSpan={columns.length + (selectable ? 1 : 0)} className="h-24 text-center text-mute">
              {emptyMessage}
            </TableCell>
          </TableRow>
        ) : (
          data.map((row) => {
            const key = keyExtractor(row);
            const isSelected = selectedKeys.includes(key);
            return (
              <TableRow key={key} className={isSelected ? "bg-ink/[0.04]" : undefined}>
                {selectable && (
                  <TableCell className="w-10">
                    <Checkbox checked={isSelected} onChange={() => toggleRow(key)} />
                  </TableCell>
                )}
                {columns.map((col) => (
                  <TableCell key={col.key} className={col.isMonospace ? "font-mono text-xs" : undefined}>
                    {col.cell(row)}
                  </TableCell>
                ))}
              </TableRow>
            );
          })
        )}
      </TableBody>
    </Table>
  );
}
