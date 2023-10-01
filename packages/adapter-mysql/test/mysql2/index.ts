import { testAdapter, Database } from "@lucia-auth/adapter-test";
import { LuciaError } from "lucia";

import { pool } from "./db.js";
import { escapeName, helper } from "../../src/utils.js";
import { getAll, mysql2Adapter } from "../../src/drivers/mysql2.js";
import { TABLE_NAMES } from "../shared.js";

import type { QueryHandler, TableQueryHandler } from "@lucia-auth/adapter-test";

class MySQL2TableQueryHandler implements TableQueryHandler {
	constructor(tableName: string) {
		this.escapedTableName = escapeName(tableName);
	}
	private escapedTableName: string;

	public get = async (): Promise<any[]> => {
		return await getAll(pool.query(`SELECT * FROM ${this.escapedTableName}`));
	};
	public insert = async (value: any): Promise<void> => {
		const [fields, placeholders, args] = helper(value);
		await pool.execute(
			`INSERT INTO ${this.escapedTableName} ( ${fields} ) VALUES ( ${placeholders} )`,
			args
		);
	};
	public clear = async (): Promise<void> => {
		await pool.execute(`DELETE FROM ${this.escapedTableName}`);
	};
}

const queryHandler: QueryHandler = {
	user: new MySQL2TableQueryHandler(TABLE_NAMES.user),
	session: new MySQL2TableQueryHandler(TABLE_NAMES.session),
	key: new MySQL2TableQueryHandler(TABLE_NAMES.key)
};

const adapter = mysql2Adapter(pool, TABLE_NAMES)(LuciaError);

await testAdapter(adapter, new Database(queryHandler));

process.exit(0);
