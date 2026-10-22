export interface TarFile {
  path: string;
  content: string | Buffer;
  type?: '0' | '2' | '5';
  mode?: number;
}

export interface TarOptions {
  prefix?: string;
  longNames?: 'pax' | 'gnu' | 'ustar';
}

export declare function makeTar(files: TarFile[], options?: TarOptions): Buffer;
export declare function makeTgz(files: Record<string, string | Buffer> | TarFile[], options?: TarOptions): Buffer;
