@metadata_processor
def add_apt_packages(metadata):
    if node.has_bundle("apt"):
        metadata.setdefault('apt', {})
        metadata['apt'].setdefault('packages', {})

        metadata['apt']['packages']['bzip2'] = {'installed': True}
        metadata['apt']['packages']['ca-certificates'] = {'installed': True}

    return metadata, DONE
