/*
 * Copyright (c) 2012, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LINUX_TEGRA_SOC_H_
#define __LINUX_TEGRA_SOC_H_

#define TEGRA20		0x20
#define TEGRA30		0x30
#define TEGRA114	0x35
#define TEGRA124	0x40

#ifndef __ASSEMBLY__

enum tegra_revision {
	TEGRA_REVISION_UNKNOWN = 0,
	TEGRA_REVISION_A01,
	TEGRA_REVISION_A02,
	TEGRA_REVISION_A03,
	TEGRA_REVISION_A03p,
	TEGRA_REVISION_A04,
	TEGRA_REVISION_MAX,
};

u32 tegra_read_straps(void);
u32 tegra_read_chipid(void);
void tegra_init_fuse(void);

extern int tegra_chip_id;
extern enum tegra_revision tegra_revision;

#if defined(CONFIG_TEGRA20_APB_DMA)
int tegra_apb_readl_using_dma(unsigned long offset, u32 *value);
int tegra_apb_writel_using_dma(u32 value, unsigned long offset);
#else
static inline int tegra_apb_readl_using_dma(unsigned long offset, u32 *value)
{
	return -EINVAL;
}
static inline int tegra_apb_writel_using_dma(u32 value, unsigned long offset)
{
	return -EINVAL;
}
#endif

#endif /* __ASSEMBLY__ */

#endif /* __LINUX_TEGRA_SOC_H_ */
