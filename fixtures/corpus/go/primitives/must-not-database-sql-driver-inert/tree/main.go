package main

import pkg "database/sql/driver"

func main() {
    _ = pkg.Bool
    _ = pkg.CoExample
    _ = pkg.DefaultParameterConverter
    _ = pkg.ErrExample
    _ = pkg.Execer
    _ = pkg.ExecerContext
    _ = pkg.Int32
    _ = pkg.IsExample
    _ = pkg.NamedValue
    _ = pkg.NamedValueChecker
    _ = pkg.NotNull
    _ = pkg.NotNull.ConvertValue
    _ = pkg.Null
    _ = pkg.Null.ConvertValue
    _ = pkg.Pinger
    _ = pkg.Queryer
    _ = pkg.QueryerContext
    _ = pkg.Result
    _ = pkg.ResultNoRows
    _ = pkg.RowExample
    _ = pkg.RowsAffected.LastInsertId
    _ = pkg.RowsAffected.RowsAffected
    _ = pkg.SessionResetter
    _ = pkg.StExample
    _ = pkg.Tx
    _ = pkg.TxOptions
    _ = pkg.ValExample
    _ = pkg.boolType.ConvertValue
    _ = pkg.boolType.String
    _ = pkg.defaultConverter.ConvertValue
    _ = pkg.int32Type.ConvertValue
    _ = pkg.noRows.LastInsertId
    _ = pkg.noRows.RowsAffected
    _ = pkg.stringType.ConvertValue
}
