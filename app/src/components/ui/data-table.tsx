import React from 'react'
import { useMemo } from 'react'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  getFilteredRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './table'
import { Input } from './input'
import { Button } from './button'

export type DataTableProps<T> = {
  columns: ColumnDef<T, any>[]
  data: T[]
  rowKey?: (row: T, index: number) => React.Key
  pageSize?: number
  searchable?: boolean
  searchPlaceholder?: string
  toolbarRender?: React.ReactNode
  loading?: boolean
}

export function DataTable<T>(props: DataTableProps<T>) {
  const { columns, data, rowKey, pageSize = 10, searchable = false, searchPlaceholder = '搜索...', toolbarRender, loading } = props
  const [sorting, setSorting] = React.useState<SortingState>([])
  const [globalFilter, setGlobalFilter] = React.useState('')

  const table = useReactTable({
    data,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  })

  React.useEffect(() => {
    table.setPageSize(pageSize)
  }, [pageSize])

  const keyGetter = useMemo(() => rowKey || ((row: T, idx: number) => (row as any)?.id ?? idx), [rowKey])

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {searchable && (
            <Input
              value={globalFilter ?? ''}
              placeholder={searchPlaceholder}
              onChange={(e) => setGlobalFilter(e.target.value)}
              className="w-64"
            />
          )}
        </div>
        <div className="flex items-center gap-2">
          {toolbarRender}
        </div>
      </div>

      <div className="overflow-x-auto border rounded-md">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => {
                  return (
                    <TableHead key={header.id} className="whitespace-nowrap select-none">
                      {header.isPlaceholder ? null : (
                        <div
                          className={header.column.getCanSort() ? 'cursor-pointer select-none' : ''}
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {{ asc: ' ▲', desc: ' ▼' }[header.column.getIsSorted() as string] ?? null}
                        </div>
                      )}
                    </TableHead>
                  )
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={columns.length}>
                  <div className="py-8 text-center text-sm text-muted-foreground">加载中...</div>
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows?.length ? (
              table.getRowModel().rows.map((row, idx) => (
                <TableRow key={keyGetter(row.original as T, idx)}>
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={columns.length}>
                  <div className="py-8 text-center text-sm text-muted-foreground">暂无数据</div>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-end gap-2">
        <div className="text-sm text-muted-foreground mr-auto">
          共 {data.length} 条，页 {table.getState().pagination.pageIndex + 1} / {table.getPageCount() || 1}
        </div>
        <Button variant="outline" size="sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>
          上一页
        </Button>
        <Button variant="outline" size="sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>
          下一页
        </Button>
      </div>
    </div>
  )
}
