fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/playbook.capnp")
        .run()
        .expect("building capnp schema");
}
